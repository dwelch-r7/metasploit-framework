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
variant = sys.argv[3] if len(sys.argv) > 3 else 'standard'
assert variant in ['standard', 'names']
names_fixture = json.loads(Path(__file__).with_name('names.json').read_text())
artifacts = Path(runtime['artifacts'])
report = {'phase': phase, 'variant': variant, 'requests': [], 'commands': []}


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
    expected_names = [names_fixture['username'], 'labadmin'] if variant == 'names' else ['labadmin', 'viewer']
    assert [row['user_name'] for row in before['users']] == expected_names
    assert len(before['accounts']) == 1
    endpoint = runtime['endpoints']['app']
    base = 'http://' + endpoint['host'] + ':' + str(endpoint['port'])
    login('labadmin', 'Module-suite-admin42!', 'login')
    assert version.encode() in request('about', '/index.php?module=Home&action=About')
    normal = request('ordinary-export', '/index.php?entryPoint=export', urllib.parse.urlencode({
        'uid': before['accounts'][0]['id'], 'module': 'Accounts', 'action': 'index'}).encode())
    assert b'Module Native Account' in normal
    normal_rows = list(csv.reader(io.StringIO(normal.decode('utf-8-sig'))))
    assert len(normal_rows) == 2
    captures = []
    for index, truth in enumerate([False, True, False, True]):
        expression = 'OR+(1=1)' if truth else 'AND+1=2'
        data = ('uid=,\\,))+' + expression + ';+--+&module=Accounts&action=index').encode()
        body = request('boolean-' + str(index), '/index.php?entryPoint=export', data)
        allowed = truth and version == '7.12.5'
        assert (b'Module Native Account' in body) == allowed
        rows = list(csv.reader(io.StringIO(body.decode('utf-8-sig'))))
        assert len(rows) == (2 if allowed else 1)
        assert rows[0] == normal_rows[0]
        captures.append({'truth': truth, 'sha256': hashlib.sha256(body).hexdigest(), 'bytes': len(body)})
    assert len({row['sha256'] for row in captures}) == (2 if version == '7.12.5' else 1)
    wire_controls = []
    for bound, truth in [(0, True), (1, False)]:
        condition = 'length(cast((select+0x61)+as+binary))+NOT+BETWEEN+0+AND+' + str(bound)
        data = ('uid=,\\,))+OR+(' + condition + ');+--+&module=Accounts&action=index').encode()
        body = request('safe-comparison-' + str(bound), '/index.php?entryPoint=export', data)
        allowed = truth and version == '7.12.5'
        rows = list(csv.reader(io.StringIO(body.decode('utf-8-sig'))))
        assert rows[0] == normal_rows[0] and len(rows) == (2 if allowed else 1)
        assert (b'Module Native Account' in body) == allowed
        wire_controls.append({'truth': truth, 'sha256': hashlib.sha256(body).hexdigest()})
    report['safe_comparison_controls'] = wire_controls
    if variant == 'names':
        edge_name = names_fixture['username']
        edge_user = next(row for row in before['users'] if row['user_name'] == edge_name)
        assert edge_user['is_admin'] == '0' and edge_user['status'] == 'Active'
        login(edge_name, names_fixture['password'], 'edge-login')
        route = urllib.parse.parse_qs(urllib.parse.urlsplit(report['requests'][-1]['final_url']).query)
        assert route.get('module') == ['Home'] and route.get('action') == ['index']
        assert version.encode() in request('edge-about', '/index.php?module=Home&action=About')
        ordinary = request('edge-ordinary-export', '/index.php?entryPoint=export', urllib.parse.urlencode({
            'uid': before['accounts'][0]['id'], 'module': 'Accounts', 'action': 'index'}).encode())
        assert b'Module Native Account' in ordinary
        edge_captures = []
        for index, truth in enumerate([False, True, False, True]):
            expression = 'OR+(1=1)' if truth else 'AND+1=2'
            data = ('uid=,\\,))+' + expression + ';+--+&module=Accounts&action=index').encode()
            body = request('edge-boolean-' + str(index), '/index.php?entryPoint=export', data)
            assert (b'Module Native Account' in body) == truth
            rows = list(csv.reader(io.StringIO(body.decode('utf-8-sig'))))
            assert len(rows) == (2 if truth else 1) and rows[0] == normal_rows[0]
            edge_captures.append({'truth': truth, 'sha256': hashlib.sha256(body).hexdigest()})
        assert len({row['sha256'] for row in edge_captures}) == 2
        report['nonadministrator_native_controls'] = edge_captures
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
