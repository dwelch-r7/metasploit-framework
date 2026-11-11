"""Use real Listmonk HTTP handlers and PostgreSQL independently of Framework."""
import base64
import hashlib
from html.parser import HTMLParser
import http.client
import json
from pathlib import Path
import re
import subprocess
import sys
from urllib.parse import urlencode

runtime = json.loads(Path(sys.argv[1]).read_text())
version, phase = sys.argv[2:4]
profile = json.loads((Path(__file__).parent / 'profiles.json').read_text())[version]
requests, commands = [], []
password = 'module-target-user-password'


def execute(service, *argv):
    completed = subprocess.run(runtime['compose'] + ['exec', '-T', service, *argv],
                               capture_output=True, timeout=25)
    commands.append({'service': service, 'argv': argv, 'exitstatus': completed.returncode,
                     'stdout_base64': base64.b64encode(completed.stdout).decode(),
                     'stderr_base64': base64.b64encode(completed.stderr).decode()})
    assert completed.returncode == 0, commands[-1]
    return completed.stdout


class Client:
    def __init__(self):
        self.cookies = {}

    def request(self, method, path, data=None, form=False):
        headers = {'Connection': 'close'}
        if self.cookies:
            headers['Cookie'] = '; '.join(k + '=' + v for k, v in self.cookies.items())
        if data is not None:
            headers['Content-Type'] = 'application/x-www-form-urlencoded' if form else 'application/json'
            data = (urlencode(data) if form else json.dumps(data)).encode()
        endpoint = runtime['endpoints']['target']
        conn = http.client.HTTPConnection(endpoint['host'], endpoint['port'], timeout=10)
        try:
            conn.request(method, path, data, headers)
            response = conn.getresponse()
            body = response.read()
            for name, value in response.getheaders():
                if name.lower() == 'set-cookie':
                    key, value = value.split(';', 1)[0].split('=', 1)
                    self.cookies[key] = value
            requests.append({'method': method, 'path': path, 'status': response.status,
                             'body_base64': base64.b64encode(body).decode()})
            return response.status, body
        finally:
            conn.close()

    def json(self, method, path, data=None):
        status, body = self.request(method, path, data)
        assert status == 200, requests[-1]
        return json.loads(body)

    def login(self, username, secret):
        status, body = self.request('GET', '/admin/login')
        assert status == 200
        nonce = re.search(rb'name="nonce"[^>]*value="([^"]+)"', body)
        assert nonce, body
        status, body = self.request('POST', '/admin/login', {
            'nonce': nonce.group(1).decode(), 'next': '/admin', 'username': username, 'password': secret}, form=True)
        return status


class Paragraphs(HTMLParser):
    def __init__(self):
        super().__init__()
        self.depth = 0
        self.items = []

    def handle_starttag(self, tag, attrs):
        if tag == 'p':
            self.depth += 1
            self.items.append('')

    def handle_endtag(self, tag):
        if tag == 'p':
            self.depth -= 1

    def handle_data(self, data):
        if self.depth:
            self.items[-1] += data


def paragraphs(body):
    parser = Paragraphs()
    parser.feed(body.decode())
    return [item.strip() for item in parser.items if item.strip()]


def snapshot():
    result = {}
    # Login timestamps and session rows legitimately change. Campaign, audience,
    # template and authorization content must survive both success and failure.
    for table in ['campaigns', 'campaign_lists', 'templates', 'lists', 'subscribers', 'subscriber_lists', 'roles']:
        query = "SELECT COALESCE(jsonb_agg(to_jsonb(row) ORDER BY to_jsonb(row)::text), '[]') FROM " + table + ' row'
        data = execute('database', 'psql', '-U', 'listmonk', '-d', 'listmonk', '-tAc', query)
        result[table] = json.loads(data)
    return result


result = {'version': version, 'phase': phase, 'status': 'starting', 'requests': requests, 'commands': commands}
try:
    native_version = execute('target', '/listmonk/listmonk', '--version').decode().strip()
    assert version in native_version, native_version
    process = execute('target', 'sh', '-c', 'for p in /proc/[0-9]*/comm; do if test "$(cat "$p" 2>/dev/null)" = listmonk; then cat "${p%/comm}/stat"; cat "${p%/comm}/status"; fi; done').decode()
    lines = process.splitlines()
    assert len([line for line in lines if re.match(r'^\d+ \(listmonk\)', line)]) == 1, process
    fields = lines[0].split()
    uid = re.search(r'^Uid:\s+(\d+)', process, re.M).group(1)
    assert uid == '1000', process
    result['identity'] = {'version': native_version, 'pid': fields[0], 'starttime': fields[21], 'uid': uid}
    names = ['MODULE_TARGET_MARKER', 'MODULE_TARGET_SPECIAL', 'MODULE_TARGET_EMPTY',
             'LISTMONK_db__host', 'LISTMONK_db__port', 'LISTMONK_db__user',
             'LISTMONK_db__password', 'LISTMONK_db__database', 'LISTMONK_app__address']
    values = {name: execute('target', 'printenv', name).decode().removesuffix('\n') for name in names}
    assert values['MODULE_TARGET_MARKER'] == runtime['artifacts']
    values['MODULE_TARGET_UNSET'] = ''
    result['environment'] = values
    anonymous = Client()
    assert anonymous.request('GET', '/api/campaigns')[0] in (401, 403)
    assert Client().login('labadmin', 'module-target-wrong-password') == 200
    admin = Client()
    assert admin.login('labadmin', 'module-target-admin-password') == 302
    about = admin.json('GET', '/api/about')
    assert about['version'].removeprefix('v') == version, about
    result['about'] = about
    state_path = Path(runtime['artifacts'], 'native-setup.json')
    if phase == 'before':
        fixtures = {}
        for name, permissions in [('reader', ['campaigns:get', 'campaigns:get_all']),
                                  ('manager', ['campaigns:get', 'campaigns:get_all', 'campaigns:manage', 'campaigns:manage_all', 'lists:get_all'])]:
            role = admin.json('POST', '/api/roles/users', {'name': 'Module target ' + name, 'permissions': permissions})['data']
            user = admin.json('POST', '/api/users', {'username': 'lab' + name, 'name': 'Lab ' + name,
                              'email': name + '@example.invalid', 'type': 'user', 'status': 'enabled',
                              'password_login': True, 'password': password, 'user_role_id': role['id']})['data']
            fixtures[name] = {'role': role, 'user': user}
        state_path.write_text(json.dumps(fixtures, indent=2) + '\n')
    else:
        fixtures = json.loads(state_path.read_text())
    result['fixtures'] = fixtures
    campaign = {'name': 'Native prerequisite', 'subject': 'Native preview only', 'lists': [1],
                'from_email': 'Lab <lab@example.invalid>', 'content_type': 'richtext',
                'messenger': 'email', 'type': 'regular', 'body': '<p>Native saved body</p>'}
    created = admin.json('POST', '/api/campaigns', campaign)['data']
    cid = created['id']
    manager = Client()
    assert manager.login('labmanager', password) == 302
    managed = manager.json('POST', '/api/campaigns', dict(campaign, name='Native manager control'))['data']
    manager.json('DELETE', '/api/campaigns/' + str(managed['id']))
    reader = Client()
    assert reader.login('labreader', password) == 302
    # This principal can preview, but cannot create or delete any campaign.
    assert reader.request('POST', '/api/campaigns', campaign)[0] == 403
    assert reader.request('DELETE', '/api/campaigns/' + str(cid))[0] == 403
    path = '/api/campaigns/' + str(cid) + '/preview'
    saved = admin.json('GET', '/api/campaigns/' + str(cid))['data']
    status, body = reader.request('POST', path, {'template_id': 1, 'content_type': 'richtext', 'body': '<p>Native ordinary preview</p>'}, form=True)
    assert status == 200 and 'Native ordinary preview' in paragraphs(body), requests[-1]
    for function, template in [('env', '{{ env "MODULE_TARGET_MARKER" }}'),
                               ('expandenv', '{{ expandenv "$MODULE_TARGET_MARKER" }}')]:
        status, body = reader.request('POST', path, {'template_id': 1, 'content_type': 'richtext', 'body': '<p>' + template + '</p>'}, form=True)
        if profile['vulnerable']:
            assert status == 200 and values['MODULE_TARGET_MARKER'] in paragraphs(body), requests[-1]
        else:
            assert status == 400 and 'function "' + function + '" not defined' in json.loads(body)['message'], requests[-1]
    result['expected_loot'] = {}
    for name, variables in [('default', names[3:]), ('custom', names[:3] + ['MODULE_TARGET_UNSET'])]:
        payload = ''.join('<p>' + var + ': {{ env "' + var + '" }}</p>' for var in variables)
        status, body = reader.request('POST', path, {'template_id': 1, 'content_type': 'richtext', 'body': payload}, form=True)
        if profile['vulnerable']:
            assert status == 200
            expected = [var + ': ' + values[var] if values[var] else var + ':' for var in variables]
            actual = paragraphs(body)
            assert all(line in actual for line in expected), actual
            result['expected_loot'][name] = '\n'.join(expected)
        else:
            assert status == 400
    assert admin.json('GET', '/api/campaigns/' + str(cid))['data'] == saved
    admin.json('DELETE', '/api/campaigns/' + str(cid))
    result['state'] = snapshot()
    result['status'] = 'native_passed'
finally:
    Path(runtime['artifacts'], 'native-' + phase + '.json').write_text(json.dumps(result, indent=2) + '\n')
print(json.dumps({'status': result['status'], 'requests': len(requests), 'version': version}))
