"""Exercise genuine OneDev administration, site resources and filesystem bytes."""
import base64
import hashlib
import http.client
import json
from pathlib import Path
import re
import subprocess
import sys
from urllib.parse import quote

runtime = json.loads(Path(sys.argv[1]).read_text())
version, phase = sys.argv[2:4]
requests, commands = [], []
result = {'version': version, 'phase': phase, 'status': 'starting', 'requests': requests, 'commands': commands}
project = 'module-target-project'
credential = base64.b64encode(b'module-admin:module-target-onedev-password').decode()


def execute(service, *argv, expected=0):
    args = runtime['compose'] + ['exec', '-T']
    if service == 'framework':
        console = runtime['console_command']
        args += ['--user', console[console.index('--user') + 1]]
    proc = subprocess.run(args + [service, *argv], capture_output=True, timeout=35)
    row = {'service': service, 'argv': argv, 'exitstatus': proc.returncode,
           'stdout_base64': base64.b64encode(proc.stdout).decode(), 'stderr_base64': base64.b64encode(proc.stderr).decode()}
    commands.append(row)
    assert proc.returncode == expected, row
    return proc.stdout


def request(method, path, data=None, auth=False, wrong=False):
    endpoint = runtime['endpoints']['target']
    conn = http.client.HTTPConnection(endpoint['host'], endpoint['port'], timeout=45)
    headers = {}
    if auth:
        headers['Authorization'] = 'Basic ' + (base64.b64encode(b'module-admin:wrong-password').decode() if wrong else credential)
    if data is not None:
        data = json.dumps(data)
        headers['Content-Type'] = 'application/json'
    try:
        conn.request(method, path, data, headers)
        response = conn.getresponse()
        body = response.read()
        row = {'method': method, 'path': path, 'authenticated': auth, 'wrong_password': wrong,
               'status': response.status, 'headers': response.getheaders(), 'body_base64': base64.b64encode(body).decode()}
        requests.append(row)
        return response.status, body
    finally:
        conn.close()


def api(method, path, data=None):
    status, body = request(method, '/~api/' + path, data, auth=True)
    assert status == 200, requests[-1]
    return json.loads(body) if body else None


def security_mode(enabled):
    security = api('GET', 'settings/security')
    if security['enableAnonymousAccess'] != enabled:
        security['enableAnonymousAccess'] = enabled
        api('POST', 'settings/security', security)
    assert api('GET', 'settings/security')['enableAnonymousAccess'] == enabled


def traverse(path):
    prefix = '/' + project + '/~site////////' + '/'.join(['%2e%2e'] * 7)
    return request('GET', prefix + quote(path, safe='/'))


try:
    status, body = request('GET', '/~api/version/server', auth=True)
    assert status == 200 and body.decode().strip('"') == version
    if phase.startswith('mode-'):
        enabled = phase.endswith('-on')
        security_mode(enabled)
        result.update(status='mode_passed', anonymous=enabled)
    else:
        initial_security = api('GET', 'settings/security')
        assert initial_security['enableAnonymousAccess'] is False
        status, _body = request('GET', '/~api/settings/security', auth=True, wrong=True)
        assert status == 401
        projects = api('GET', 'projects?offset=0&count=100')
        matches = [row for row in projects if row['name'] == project]
        if not matches:
            project_id = api('POST', 'projects', {'name': project, 'codeManagement': True, 'issueManagement': True})
        else:
            assert len(matches) == 1
            project_id = matches[0]['id']
        assert isinstance(project_id, int)
        site_dir = '/opt/onedev/site/projects/' + str(project_id) + '/site'
        execute('target', 'bash', '-c', 'mkdir -p "$1"; printf "%s\\n" "Native ordinary OneDev site marker" >"$1/native.txt"', 'fixture', site_dir)
        execute('target', 'bash', '-c', "printf '\\000\\377AB\\n' >/tmp/module-target-binary.bin")
        files = {}
        paths = {'default': '/etc/passwd', 'binary': '/tmp/module-target-binary.bin'}
        paths.update({key: '/opt/module-target-files/' + name for key, name in {
            'short': 'short.txt', 'empty': 'empty.txt', 'unicode': 'unicode.txt',
            'space': 'space name.txt', 'large': 'large.txt', 'error_phrase': 'error-phrase.txt'}.items()})
        for kind, path in paths.items():
            raw = execute('target', 'cat', path)
            files[kind] = {'path': path, 'base64': base64.b64encode(raw).decode(), 'sha256': hashlib.sha256(raw).hexdigest()}
            if kind != 'binary':
                files[kind]['text'] = raw.decode()
            if path.startswith('/opt/module-target-files/'):
                assert raw == (Path(__file__).parent / 'files' / Path(path).name).read_bytes()
        assert base64.b64decode(files['binary']['base64']) == bytes([0, 255, 65, 66, 10])
        assert len(base64.b64decode(files['large']['base64'])) > 32768
        execute('target', 'test', '!', '-e', '/opt/module-target-files/missing-task.txt')
        assert execute('target', 'stat', '-c', '%F', '/opt/module-target-files').strip() == b'directory'
        modes = {}
        for enabled in [False, True]:
            security_mode(enabled)
            status, home = request('GET', '/')
            assert status == 200
            status, _body = request('GET', '/~api/projects/' + str(project_id))
            assert status == 401
            status, _body = request('HEAD', '/' + project + '/~site')
            assert status == 200
            status, body = request('GET', '/' + project + '/~site/native.txt')
            assert status == 200 and body == b'Native ordinary OneDev site marker\n'
            status, body = request('HEAD', '/module-target-missing/~site')
            assert status == 404
            status, body = request('HEAD', '/module-target-absent/~site')
            assert status == 404
            documents = {}
            for kind, file in files.items():
                status, body = traverse(file['path'])
                if version == '11.0.8':
                    assert status == 200 and body == base64.b64decode(file['base64']), (kind, requests[-1])
                else:
                    assert status == 500 and body == b'Invalid request path', requests[-1]
                documents[kind] = {'status': status, 'base64': base64.b64encode(body).decode()}
            negatives = {}
            for kind, path in [('missing', '/opt/module-target-files/missing-task.txt'), ('directory', '/opt/module-target-files')]:
                status, body = traverse(path)
                if version == '11.0.9':
                    assert status == 500 and body == b'Invalid request path'
                elif kind == 'missing':
                    assert status == 200 and body.startswith(b'Site file not found: ')
                else:
                    assert status == 200, requests[-1]
                    headers = dict((key.lower(), value) for key, value in requests[-1]['headers'])
                    assert headers['content-type'].startswith('text/html'), requests[-1]
                    assert b'var redirect = ' in body and b'window.location.replace(redirect)' in body, requests[-1]
                    assert re.search(rb"var redirect = '[^']+/';", body), requests[-1]
                negatives[kind] = {'status': status, 'base64': base64.b64encode(body).decode()}
            modes[str(enabled).lower()] = {'anonymous': enabled, 'home_base64': base64.b64encode(home).decode(),
                                          'home_version': re.search(rb'OneDev ([\d.]+)', home).group(1).decode() if re.search(rb'OneDev ([\d.]+)', home) else None,
                                          'documents': documents, 'negative_documents': negatives}
        security_mode(False)
        stable_project = api('GET', 'projects/' + str(project_id))
        fields = ['id', 'name', 'path', 'description', 'defaultRole', 'codeManagement', 'issueManagement']
        stable_project = {key: stable_project.get(key) for key in fields}
        assert len(api('GET', 'projects?offset=0&count=100')) == 1
        process = execute('target', 'sh', '-c', 'for name in /proc/[0-9]*/comm; do if test "$(cat "$name" 2>/dev/null)" = java; then cat "${name%/comm}/stat"; fi; done').decode().splitlines()
        assert len(process) == 1
        fields = process[0].split()
        identity = {'java_pid': fields[0], 'java_starttime': fields[21]}
        cgroups = execute('target', 'sh', '-c', 'cat /sys/fs/cgroup/memory.peak /sys/fs/cgroup/memory.events /sys/fs/cgroup/pids.peak /sys/fs/cgroup/pids.events').decode()
        assert 'oom 0' in cgroups and 'oom_kill 0' in cgroups
        assert all(line == 'max 0' for line in cgroups.splitlines() if line.startswith('max ')), cgroups
        owner = runtime['console_command'][runtime['console_command'].index('--user') + 1]
        host = runtime['module_endpoints']['target']['host']
        code = "require 'socket'; begin; Socket.tcp(ARGV[0],1,connect_timeout:2).close; abort 'Unexpected open port'; rescue Errno::ECONNREFUSED; puts Process.uid.to_s+':'+Process.gid.to_s; end"
        assert execute('framework', 'ruby', '-e', code, host).decode().strip() == owner
        wordlist = '/usr/src/metasploit-framework/test/module_targets/onedev_file/wordlists/projects.txt'
        assert execute('framework', 'cat', wordlist) == (Path(__file__).parent / 'wordlists/projects.txt').read_bytes()
        missing = '/usr/src/metasploit-framework/test/module_targets/onedev_file/wordlists/missing-projects.txt'
        assert execute('framework', 'cat', missing) == (Path(__file__).parent / 'wordlists/missing-projects.txt').read_bytes()
        execute('framework', 'test', '!', '-e', '/opt/module-target-wordlist-missing')
        result.update(status='native_passed', files=files, modes=modes, identity=identity, project=stable_project,
                      security=api('GET', 'settings/security'), cgroups=cgroups,
                      refused_port={'host': host, 'port': 1, 'owner': owner})
finally:
    Path(runtime['artifacts'], 'native-' + phase + '.json').write_text(json.dumps(result, indent=2) + '\n')
print(json.dumps({'status': result['status'], 'phase': phase, 'requests': len(requests)}))
