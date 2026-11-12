"""Genuine 4gaBoards API, source, authentication and PostgreSQL controls."""
import base64
import http.client
import json
from pathlib import Path
import subprocess
import sys

runtime = json.loads(Path(sys.argv[1]).read_text())
profile, phase = sys.argv[2:4]
requests, commands = [], []
result = {'status': 'starting', 'profile': profile, 'phase': phase,
          'requests': requests, 'commands': commands}
profiles = json.loads((Path(__file__).parent / 'profiles.json').read_text())
version = '3.3.9' if profile == 'fixed' else '3.3.8'
reader_email = 'native-reader@module-target.invalid'
reader_password = 'Native-4ga-Control-Password!47#'
admin_email = 'administrator@module-target.invalid'
public_fields = {'id', 'name', 'username', 'avatarUrl', 'deletedAt'}


def execute(service, *argv, expected=0):
    process = subprocess.run(runtime['compose'] + ['exec', '-T', service, *argv],
                             capture_output=True, timeout=60)
    row = {'service': service, 'argv': argv, 'exit': process.returncode,
           'stdout_base64': base64.b64encode(process.stdout).decode(),
           'stderr_base64': base64.b64encode(process.stderr).decode()}
    commands.append(row)
    assert process.returncode == expected, row
    return process.stdout


def sql(database, query, rejected=False):
    user = 'module_app' if database == 'module_app' else 'module_framework'
    password = 'module-target-application-db-password' if database == 'module_app' else 'module-target-framework-db-password'
    return execute('reporting_db', 'env', 'PGPASSWORD=' + ('module-target-rejected-password' if rejected else password),
                   'psql', '-h', '127.0.0.1', '-U', user, '-d', database,
                   '-v', 'ON_ERROR_STOP=1', '-Atc', query, expected=2 if rejected else 0).decode().strip()


def request(path, method='GET', data=None, token=None):
    endpoint = runtime['endpoints']['target']
    connection = http.client.HTTPConnection(endpoint['host'], endpoint['port'], timeout=20)
    headers = {'Content-Type': 'application/json'}
    if token:
        headers['Authorization'] = 'Bearer ' + token
    try:
        connection.request(method, path, body=json.dumps(data).encode() if data is not None else None, headers=headers)
        response = connection.getresponse()
        body = response.read()
        requests.append({'method': method, 'path': path, 'authenticated': bool(token),
                         'status': response.status, 'body_base64': base64.b64encode(body).decode()})
        try:
            parsed = json.loads(body)
        except ValueError:
            parsed = None
        return response.status, body, parsed
    finally:
        connection.close()


try:
    result['postgres_version'] = sql('module_targets', 'SELECT version()')
    assert not sql('module_targets', 'SELECT 1', rejected=True)
    status, body, _ = request('/')
    assert status == 200
    result['ordinary_sha256'] = __import__('hashlib').sha256(body).hexdigest()
    if profile == 'unrelated':
        assert b'It works!' in body
        assert request('/api/register', 'POST', {'email': reader_email})[0] == 404
        result['identity'] = execute('target', 'cat', '/proc/1/stat').decode().split(') ', 1)[1].split()[19]
    else:
        assert b'<title>4ga Boards</title>' in body
        source_script = r'''
        const fs=require('fs'),crypto=require('crypto');let files={};
        for(let path of JSON.parse(process.argv[1])){let bytes=fs.readFileSync(path);files[path]=crypto.createHash('sha256').update(bytes).digest('hex');}
        let stat=fs.readFileSync('/proc/1/stat').toString();let tail=stat.slice(stat.lastIndexOf(')')+2).trim().split(/\s+/);
        console.log(JSON.stringify({files,identity:{start_time:tail[19],command:fs.readFileSync('/proc/1/cmdline').toString()},
          memory_events:fs.readFileSync('/sys/fs/cgroup/memory.events').toString(),pids_events:fs.readFileSync('/sys/fs/cgroup/pids.events').toString()}));
        '''
        state = json.loads(execute('target', 'node', '-e', source_script,
                                   json.dumps(list(profiles[version]['files_sha256']))))
        assert state['files'] == profiles[version]['files_sha256']
        assert state['identity']['command'] == 'node\0app.js\0--prod\0'
        assert all(int(line.split()[1]) == 0 for line in state['memory_events'].splitlines())
        assert state['pids_events'].strip() == 'max 0'
        result.update(state)
        result['schema_count'] = int(sql('module_app', "SELECT count(*) FROM information_schema.tables WHERE table_schema='public'"))
        assert result['schema_count'] == 29
        assert not sql('module_app', 'SELECT 1', rejected=True)
        assert request('/api/users')[0] == 401
        assert request('/api/users', token='module-target-invalid-token')[0] == 401
        assert request('/api/access-tokens', 'POST', {'emailOrUsername': 'module_admin', 'password': 'module-target-rejected-password'})[0] == 401
        status, _, data = request('/api/access-tokens', 'POST', {'emailOrUsername': 'module_admin', 'password': 'module-target-admin-password'})
        assert status == 200 and isinstance(data['item'], str)
        admin_token = data['item']
        if phase == 'before':
            sql('module_app', "UPDATE user_account SET phone='+1-202-555-0123',organization='Module Target & Research',sso_github_email='fixture-github@module-target.invalid' WHERE email='administrator@module-target.invalid'")
        status, _, data = request('/api/users', token=admin_token)
        assert status == 200
        admin = next(row for row in data['items'] if row['email'] == admin_email)
        assert admin['isAdmin'] and admin['phone'] == '+1-202-555-0123'
        assert admin['organization'] == 'Module Target & Research'
        assert admin['ssoGithubEmail'] == 'fixture-github@module-target.invalid'
        result['administrator'] = admin
        registration = {'email': reader_email, 'password': reader_password, 'name': 'Native Reader', 'policy': True}
        if profile == 'locked':
            assert request('/api/register', 'POST', registration)[0] == 403
            assert [row['email'] for row in data['items']] == [admin_email]
            result['expected_users'] = [admin]
        else:
            if phase == 'before':
                assert request('/api/register', 'POST', registration)[0] == 200
            status, _, auth = request('/api/access-tokens', 'POST', {'emailOrUsername': reader_email, 'password': reader_password})
            assert status == 200
            status, _, limited = request('/api/users', token=auth['item'])
            assert status == 200
            other = next(row for row in limited['items'] if row['id'] == admin['id'])
            if profile == 'fixed':
                assert set(other) == public_fields
            else:
                assert other['email'] == admin_email and other['phone'] == admin['phone']
                assert other['organization'] == admin['organization'] and other['ssoGithubEmail'] == admin['ssoGithubEmail']
            assert request('/api/register', 'POST', registration)[0] == 409
            result['expected_users'] = limited['items']
            assert len(limited['items']) == 2
        result['core'] = json.loads(sql('module_app', 'SELECT json_build_object(\'registration_enabled\',registration_enabled,\'local_registration_enabled\',local_registration_enabled) FROM core WHERE id=0'))
        assert result['core'] == {'registration_enabled': profile != 'locked', 'local_registration_enabled': True}
    result['status'] = 'native_passed'
except (AssertionError, OSError, ValueError, KeyError, StopIteration, subprocess.SubprocessError, http.client.HTTPException) as error:
    result.update(status='native_failed', error=str(error))
    raise
finally:
    Path(runtime['artifacts'], 'native-' + phase + '.json').write_text(json.dumps(result, indent=2) + '\n')
