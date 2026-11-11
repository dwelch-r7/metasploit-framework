"""Independent real browser, file and WebDriver lifecycle controls."""
import base64
import hashlib
from html.parser import HTMLParser
import http.client
import json
from pathlib import Path
import subprocess
import sys
import time
from urllib.parse import quote, urlsplit

runtime = json.loads(Path(sys.argv[1]).read_text())
profile_key, phase = sys.argv[2:4]
profile = json.loads((Path(__file__).parent / 'profiles.json').read_text())[profile_key]
legacy = profile['version'].startswith('3.')
requests, commands = [], []
result = {'profile': profile_key, 'phase': phase, 'status': 'starting', 'requests': requests, 'commands': commands}


def execute(service, *argv, expected_exit=0):
    options = ['exec', '-T']
    user = None
    if service == 'framework':
        console = runtime['console_command']
        user = console[console.index('--user') + 1]
        options += ['--user', user]
    completed = subprocess.run(runtime['compose'] + options + [service, *argv], capture_output=True, timeout=25)
    commands.append({'service': service, 'user': user, 'argv': argv, 'exitstatus': completed.returncode,
                     'stdout_base64': base64.b64encode(completed.stdout).decode(),
                     'stderr_base64': base64.b64encode(completed.stderr).decode()})
    assert completed.returncode == expected_exit, commands[-1]
    return completed.stdout


def request(method, path, data=None):
    endpoint = runtime['endpoints']['target']
    connection = http.client.HTTPConnection(endpoint['host'], endpoint['port'], timeout=80)
    started = time.monotonic()
    try:
        connection.request(method, path, None if data is None else json.dumps(data),
                           {'Content-Type': 'application/json', 'Connection': 'close'})
        response = connection.getresponse()
        body = response.read()
        requests.append({'method': method, 'path': path, 'data': data, 'status': response.status,
                         'elapsed': time.monotonic() - started, 'body_base64': base64.b64encode(body).decode()})
        return response.status, json.loads(body)
    finally:
        connection.close()


def successful(method, path, data=None):
    status, document = request(method, path, data)
    assert status == 200, requests[-1]
    return document


def sessions():
    status = successful('GET', '/wd/hub/status' if legacy else '/status')
    if legacy:
        assert status['value']['build']['version'] == profile['version'], status
        rows = successful('GET', '/wd/hub/sessions')['value']
        return [row['id'] for row in rows], status
    assert len(status['value']['nodes']) == 1, status
    node = status['value']['nodes'][0]
    assert node['version'].startswith(profile['version'] + ' '), node
    return [slot['session']['sessionId'] for slot in node['slots'] if slot['session'] is not None], status


class Pre(HTMLParser):
    def __init__(self):
        super().__init__()
        self.inside = False
        self.count = 0
        self.text = ''

    def handle_starttag(self, tag, attrs):
        if tag == 'pre':
            self.count += 1
            self.inside = True

    def handle_endtag(self, tag):
        if tag == 'pre':
            self.inside = False

    def handle_data(self, data):
        if self.inside:
            self.text += data


def document(session, url):
    status, navigation = request('POST', '/wd/hub/session/' + session + '/url', {'url': url})
    html = successful('GET', '/wd/hub/session/' + session + '/source')['value']
    parser = Pre()
    parser.feed(html)
    result = {'url': url, 'navigation_status': status, 'navigation': navigation,
              'pre_count': parser.count, 'text': parser.text, 'source': html}
    if status == 200 and parser.count == 0:
        result['current_url'] = successful('GET', '/wd/hub/session/' + session + '/url')['value']
        script = 'return {href: location.href, content_type: document.contentType, body_text: document.body.textContent};'
        result['metadata'] = successful('POST', '/wd/hub/session/' + session + '/execute/sync', {'script': script, 'args': []})
    return result


def empty_text_document(row):
    metadata = row.get('metadata', {}).get('value', {})
    expected_scheme = urlsplit(row['url']).scheme
    actual_scheme = urlsplit(row.get('current_url', '')).scheme
    allowed_schemes = ('http', 'https') if expected_scheme in ('http', 'https') else (expected_scheme,)
    return (row['navigation_status'] == 200 and row['pre_count'] == 0 and
            metadata.get('content_type') == 'text/plain' and metadata.get('body_text') == '' and
            metadata.get('href') == row.get('current_url') and actual_scheme in allowed_schemes)


try:
    active, status = sessions()
    result['initial_status'] = status
    if phase.startswith('audit-'):
        result['active_before_recovery'] = active
        recovered = []
        # A failed owning cleanup must remain a failed assertion. Recover only
        # that owned browser session so it cannot poison subsequent examples.
        for identifier in active:
            successful('DELETE', '/wd/hub/session/' + identifier)
            recovered.append(identifier)
        remaining, _status = sessions()
        assert remaining == [], remaining
        result.update(recovered=recovered, status='session_audit_passed')
    else:
        assert active == [], active
        assert status['value']['ready'] is True, status
        uid = execute('target', 'id', '-u').decode().strip()
        assert uid == '1200', uid
        script = 'for p in /proc/[0-9]*/comm; do if test "$(cat "$p" 2>/dev/null)" = java; then cat "${p%/comm}/stat"; fi; done'
        processes = execute('target', 'sh', '-c', script).decode().splitlines()
        assert len(processes) == 1, processes
        fields = processes[0].split()
        if phase == 'before':
            command = 'python3 -u /opt/module-target-http.py /opt/module-target-files 8123 </dev/null >/tmp/module-target-http.log 2>&1 & echo "$!" >/tmp/module-target-http.pid'
            execute('target', 'sh', '-c', command)
        http_pid = execute('target', 'cat', '/tmp/module-target-http.pid').decode().strip()
        http_stat = execute('target', 'cat', '/proc/' + http_pid + '/stat').decode().split()
        result['identity'] = {'uid': uid, 'java_pid': fields[0], 'java_starttime': fields[21],
                              'http_pid': http_pid, 'http_starttime': http_stat[21]}
        paths = {'default': '/etc/passwd', 'hostname': '/etc/hostname',
                 'short': '/opt/module-target-files/short.txt', 'empty': '/opt/module-target-files/empty.txt',
                 'unicode': '/opt/module-target-files/unicode.txt', 'large': '/opt/module-target-files/large.txt',
                 'nested': '/opt/module-target-files/nested/settings.txt',
                 'space': '/opt/module-target-files/space name.txt',
                 'empty_space': '/opt/module-target-files/empty space.txt'}
        files = {}
        for key, path in paths.items():
            body = execute('target', 'cat', path)
            files[key] = {'path': path, 'base64': base64.b64encode(body).decode(),
                          'sha256': hashlib.sha256(body).hexdigest(), 'text': body.decode('utf-8-sig')}
        assert files['empty']['base64'] == '' and len(base64.b64decode(files['large']['base64'])) > 32768
        result['files'] = files
        execute('target', 'test', '!', '-e', '/opt/module-target-files/module-target-missing.txt')
        execute('target', 'test', '-f', '/etc/shadow')
        execute('target', 'cat', '/etc/shadow', expected_exit=1)
        served = execute('target', 'curl', '--fail', '--silent', '--show-error', '--retry', '5',
                         '--retry-connrefused', '--retry-max-time', '5', 'http://127.0.0.1:8123/short.txt')
        assert served == base64.b64decode(files['short']['base64'])
        options_key = {'firefox': 'moz:firefoxOptions', 'chrome': 'goog:chromeOptions', 'MicrosoftEdge': 'ms:edgeOptions'}[profile['browser']]
        created = successful('POST', '/wd/hub/session', {'capabilities': {'alwaysMatch': {
            'browserName': profile['browser'], options_key: {}}}})
        session = created.get('sessionId') or created['value']['sessionId']
        result['native_session'] = created
        try:
            active, _status = sessions()
            assert active == [session], active
            result['native_active_session_ids'] = active
            capabilities = created['value'].get('capabilities', created['value'])
            assert capabilities['browserName'] == profile['browser'], capabilities
            result['browser_version'] = capabilities.get('browserVersion', capabilities.get('version'))
            assert result['browser_version']
            negatives = {}
            for key, path in [('missing', '/opt/module-target-files/module-target-missing.txt'), ('denied', '/etc/shadow')]:
                row = document(session, 'file://' + quote(path, safe='/'))
                assert row['pre_count'] == 0, row
                negatives[key] = row
            result['negative_documents'] = negatives
            html_path = '/opt/module-target-files/blank.html'
            html_bytes = execute('target', 'cat', html_path)
            assert html_bytes
            html = document(session, 'file://' + html_path)
            assert html['navigation_status'] == 200 and html['pre_count'] == 0, html
            assert html['metadata']['value']['content_type'] == 'text/html' and html['metadata']['value']['body_text'] == '', html
            html.update(path=html_path, base64=base64.b64encode(html_bytes).decode(), sha256=hashlib.sha256(html_bytes).hexdigest())
            result['unsupported_document'] = html
            for key, entry in files.items():
                row = document(session, 'file://' + quote(entry['path'], safe='/'))
                if entry['text'] == '':
                    assert row['navigation_status'] == 200 and (row['pre_count'] == 1 or empty_text_document(row)), row
                else:
                    assert row['navigation_status'] == 200 and row['pre_count'] == 1, row
                assert row['text'] == entry['text'], (key, row)
                entry['browser_document'] = row
            row = document(session, 'http://127.0.0.1:8123/short.txt')
            assert row['navigation_status'] == 200 and row['pre_count'] == 1 and row['text'] == files['short']['text'], row
            result['http_document'] = row
            row = document(session, 'http://127.0.0.1:8123/redirect-empty.txt')
            assert row['navigation_status'] == 200 and row['text'] == '', row
            assert row['pre_count'] == 1 or empty_text_document(row), row
            result['http_empty_document'] = row
        finally:
            successful('DELETE', '/wd/hub/session/' + session)
        active, result['final_status'] = sessions()
        assert active == [], active
        result['cgroups'] = execute('target', 'sh', '-c', 'cat /sys/fs/cgroup/memory.peak /sys/fs/cgroup/memory.events /sys/fs/cgroup/pids.peak /sys/fs/cgroup/pids.events').decode()
        assert 'oom_kill 0' in result['cgroups'] and 'oom 0' in result['cgroups']
        pid_events = execute('target', 'cat', '/sys/fs/cgroup/pids.events').decode()
        result['pid_events'] = {key: int(value) for key, value in (line.split() for line in pid_events.splitlines())}
        assert result['pid_events']['max'] == 0, result['pid_events']
        host = runtime['module_endpoints']['target']['host']
        code = "begin; Socket.tcp(ARGV.fetch(0), 1, connect_timeout: 2) { abort 'Unexpected open port' }; rescue Errno::ECONNREFUSED; puts 'REFUSED'; end"
        assert execute('framework', 'ruby', '-rsocket', '-e', code, host).strip() == b'REFUSED'
        result['refused_port'] = {'host': host, 'port': 1, 'same_owning_console_user': True}
        result['http_log'] = execute('target', 'cat', '/tmp/module-target-http.log').decode()
        result['status'] = 'native_passed'
finally:
    Path(runtime['artifacts'], 'native-' + phase + '.json').write_text(json.dumps(result, indent=2) + '\n')
print(json.dumps({'status': result['status'], 'phase': phase, 'requests': len(requests)}))
