#!/usr/bin/env python3
"""Genuine SuiteCRM login/export controls, independent of Framework."""
from html.parser import HTMLParser
from pathlib import Path
import base64
import csv
import hashlib
import http.cookiejar
import io
import json
import subprocess
import sys
import urllib.parse
import urllib.request

runtime = json.loads(Path(sys.argv[1]).read_text())
phase = sys.argv[2]
artifacts = Path(runtime['artifacts'])
report = {'phase': phase, 'requests': [], 'commands': []}


def command(label, role, *arguments):
    argv = runtime['compose'] + ['exec', '-T', role, *arguments]
    result = subprocess.run(argv, capture_output=True, timeout=30)
    report['commands'].append({'label': label, 'argv': argv, 'exit': result.returncode,
                               'stdout_base64': base64.b64encode(result.stdout).decode(),
                               'stderr': result.stderr.decode(errors='replace')})
    assert result.returncode == 0, (label, result.stderr)
    return result.stdout


class Fields(HTMLParser):
    def __init__(self):
        super().__init__()
        self.fields = {}

    def handle_starttag(self, tag, attributes):
        values = dict(attributes)
        if tag == 'input' and values.get('name'):
            self.fields[values['name']] = values.get('value', '')


def request(label, path, data=None):
    query = urllib.request.Request(base + path, data=data)
    response = client.open(query, timeout=20)
    body = response.read()
    report['requests'].append({'label': label, 'method': query.get_method(), 'url': query.full_url,
                               'sent_base64': base64.b64encode(data).decode() if data else None,
                               'status': response.status, 'final_url': response.url,
                               'headers': list(response.headers.items()),
                               'body_base64': base64.b64encode(body).decode()})
    return body


def login(username, password, label):
    global client
    client = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
    body = request(label + '-form', '/index.php?module=Users&action=Login')
    fields = Fields()
    fields.feed(body.decode(errors='replace'))
    assert 'user_name' in fields.fields and 'username_password' in fields.fields
    form = {key: value for key, value in fields.fields.items()
            if key in ['module', 'action', 'return_module', 'return_action', 'csrf_token']}
    form.update(module='Users', action='Authenticate', user_name=username,
                username_password=password, Login='Log In')
    return request(label, '/index.php', urllib.parse.urlencode(form).encode())


try:
    before = json.loads(command('snapshot-before', 'app', 'php', '/opt/module-target/control.php'))
    version = before['version']
    releases = json.loads(Path(__file__).with_name('releases.json').read_text())
    assert before['export_sha256'] == releases[version]['export_sha256']
    assert before['php'] == '7.4.33'
    assert [row['user_name'] for row in before['users']] == ['labadmin', 'viewer']
    assert len(before['accounts']) == 1
    endpoint = runtime['endpoints']['app']
    base = 'http://' + endpoint['host'] + ':' + str(endpoint['port'])
    login('labadmin', 'Module-suite-admin42!', 'login')
    assert version.encode() in request('about', '/index.php?module=Home&action=About')
    normal = request('ordinary-export', '/index.php?entryPoint=export', urllib.parse.urlencode({
        'uid': before['accounts'][0]['id'], 'module': 'Accounts', 'action': 'index'}).encode())
    assert b'Module Native Account' in normal
    captures = []
    for index, truth in enumerate([False, True, False, True]):
        expression = 'OR+(1=1)' if truth else 'AND+1=2'
        data = ('uid=,\\,))+' + expression + ';+--+&module=Accounts&action=index').encode()
        body = request('boolean-' + str(index), '/index.php?entryPoint=export', data)
        allowed = truth and version == '7.12.5'
        assert (b'Module Native Account' in body) == allowed
        rows = list(csv.reader(io.StringIO(body.decode('utf-8-sig'))))
        assert len(rows) == (2 if allowed else 1)
        captures.append({'truth': truth, 'sha256': hashlib.sha256(body).hexdigest(), 'bytes': len(body)})
    assert len({row['sha256'] for row in captures}) == (2 if version == '7.12.5' else 1)
    failed_login = login('labadmin', 'Module-wrong-password42!', 'wrong-login')
    failed_location = report['requests'][-1]['final_url']
    denied = request('denied-export', '/index.php?entryPoint=export', urllib.parse.urlencode({
        'uid': before['accounts'][0]['id'], 'module': 'Accounts', 'action': 'index'}).encode())
    assert b'Module Native Account' not in denied
    for body, location in [(failed_login, failed_location),
                           (denied, report['requests'][-1]['final_url'])]:
        fields = Fields()
        fields.feed(body.decode(errors='replace'))
        assert 'user_name' in fields.fields and 'username_password' in fields.fields
        assert b'SuiteCRM' in body
        query = urllib.parse.parse_qs(urllib.parse.urlsplit(location).query)
        assert query.get('module') == ['Users'] and query.get('action') == ['Login']
    report['wrong_password_denied'] = True
    after = json.loads(command('snapshot-after', 'app', 'php', '/opt/module-target/control.php'))
    assert before == after
    report.update(status='passed', snapshot=before, boolean_exports=captures)
finally:
    (artifacts / ('native-suitecrm-' + phase + '.json')).write_text(json.dumps(report, indent=2) + '\n')
print(json.dumps({'status': report['status'], 'version': version}))
