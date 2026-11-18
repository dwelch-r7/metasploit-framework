"""Use Airflow's real UI, API, scheduler and ORM before trusting owner results."""
from pathlib import Path
from html.parser import HTMLParser
import base64
import hashlib
import http.cookiejar
import json
import os
import shlex
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

runtime = json.loads(Path(sys.argv[1]).read_text())
phase, mode = sys.argv[2:4]
assert phase in ['before', 'after']
assert mode in ['vulnerable', 'fixed', 'denied', 'missing', 'patched', 'prefix']
config = json.loads((Path(__file__).parent / 'profiles.json').read_text())
release = '1.10.11' if mode == 'fixed' else '1.10.10'
prefix = '/airflow' if mode == 'prefix' else ''
endpoint = runtime['endpoints']['app']
base = 'http://{}:{}'.format(endpoint['host'], endpoint['port']) + prefix
out = Path(runtime['artifacts']) / ('native-airflow-' + phase)
out.mkdir()
proof = {'commands': [], 'http': [], 'phase': phase, 'mode': mode}
nonce = '{}-{}-{}'.format(phase, os.getpid(), time.time_ns())


def command(label, *args):
    argv = runtime['compose'] + ['exec', '-T', 'app'] + list(args)
    process = subprocess.run(argv, capture_output=True, timeout=40)
    proof['commands'].append({'label': label, 'argv': argv, 'exit': process.returncode,
                              'stdout_base64': base64.b64encode(process.stdout).decode(),
                              'stderr_base64': base64.b64encode(process.stderr).decode()})
    if process.returncode:
        raise RuntimeError(label + ': ' + process.stderr.decode(errors='replace'))
    return process.stdout


def control(label, reset=None):
    args = ['python', '/opt/module-target/control.py']
    if reset is not None:
        args += ['reset', json.dumps(reset)]
    output = command(label, *args).decode(errors='replace')
    values = [json.loads(line[len('CONTROL_JSON='):]) for line in output.splitlines() if line.startswith('CONTROL_JSON=')]
    assert len(values) == 1
    return values[0]


def request(label, path, data=None, client=None, expected=200, json_data=False):
    headers = {'Content-Type': 'application/json'} if json_data else {}
    query = urllib.request.Request(base + path, data=data, headers=headers)
    try:
        response = (client.open(query, timeout=15) if client else urllib.request.urlopen(query, timeout=15))
    except urllib.error.HTTPError as error:
        response = error
    raw = response.read()
    index = len(proof['http'])
    (out / (str(index) + '-' + label + '.body')).write_bytes(raw)
    proof['http'].append({'label': label, 'method': query.get_method(), 'url': query.full_url,
                          'status': response.status, 'final_url': response.url,
                          'sent_base64': base64.b64encode(data).decode() if data else None,
                          'headers': list(response.headers.items()),
                          'sha256': hashlib.sha256(raw).hexdigest()})
    assert response.status == expected, (label, response.status, raw[:400])
    return raw


class Form(HTMLParser):
    def __init__(self):
        super().__init__()
        self.fields = {}

    def handle_starttag(self, tag, attrs):
        fields = dict(attrs)
        if tag == 'input' and fields.get('name'):
            self.fields[fields['name']] = fields.get('value', '')


def login(label, password):
    client = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
    form = Form()
    form.feed(request(label + '-form', '/admin/airflow/login', client=client).decode())
    assert '_csrf_token' in form.fields
    form.fields.update(username=config['username'], password=password)
    body = request(label, '/admin/airflow/login', urllib.parse.urlencode(form.fields).encode(), client=client)
    return '/login' not in proof['http'][-1]['final_url'] and b'sign in to airflow' not in body.lower()


def trigger(label, message):
    run_id = 'module-target-' + nonce + '-' + label
    data = json.dumps({'run_id': run_id, 'conf': {'message': message}}).encode()
    dag = '/api/experimental/dags/' + config['dag_id']
    info = json.loads(request(label + '-trigger', dag + '/dag_runs', data, json_data=True))
    assert info['run_id'] == run_id
    deadline = time.monotonic() + 100
    attempt = 0
    while time.monotonic() < deadline:
        state = json.loads(request(label + '-state-' + str(attempt), dag + '/dag_runs/' + urllib.parse.quote(info['execution_date'], safe='')))['state']
        if state in ['success', 'failed']:
            assert state == 'success'
            return info
        attempt += 1
        time.sleep(min(2, attempt * .25))
    raise RuntimeError('Native scheduler did not finish ' + run_id)


def file_state(label, path):
    code = "import base64,json,sys;from pathlib import Path;p=Path(sys.argv[1]);print(json.dumps({'exists':p.is_file(),'uid':p.stat().st_uid if p.is_file()else None,'base64':base64.b64encode(p.read_bytes()).decode()if p.is_file()else None}))"
    return json.loads(command(label, 'python', '-c', code, path))


def canonical(state):
    return {key: state[key] for key in ['version', 'uid', 'hostname', 'deployment', 'users', 'dags', 'runs', 'tasks', 'configuration']}


try:
    before = control('before')
    proof['before'] = before
    assert before['version'] == release and before['uid'] == config['uid']
    assert before['deployment']['mode'] == mode
    deployed = None if mode == 'missing' else config['versions']['1.10.11' if mode == 'patched' else release]
    assert before['deployment']['deployed_dag_sha256'] == deployed
    assert before['runs'] == before['tasks'] == []
    assert len(before['users']) == 1 and before['users'][0]['username'] == config['username']
    assert before['users'][0]['superuser'] is True and before['users'][0]['password'].startswith('$2b$')
    assert len(before['scheduler_jobs']) == 1 and before['scheduler_jobs'][0]['state'] == 'running'
    assert before['configuration']['core.executor'] == 'SequentialExecutor'
    page = request('login-page', '/admin/airflow/login')
    assert b'sign in to airflow' in page.lower() and b'_csrf_token' in page
    assert ('https://airflow.apache.org/docs/' + release).encode() in page
    assert login('valid-login', config['password'])
    assert not login('wrong-login', 'Module-invalid-password42!')
    dag = '/api/experimental/dags/' + config['dag_id']
    if mode == 'denied':
        assert before['configuration']['api.auth_backend'] == 'airflow.api.auth.backend.deny_all'
        request('api-denied', '/api/experimental/test', expected=403)
        request('task-denied', dag + '/tasks/' + config['task_id'], expected=403)
        request('create-denied', dag + '/dag_runs', b'{"conf":{"message":"ordinary"}}', expected=403, json_data=True)
    else:
        assert before['configuration']['api.auth_backend'] == 'airflow.api.auth.backend.default'
        assert json.loads(request('api', '/api/experimental/test')) == {'status': 'OK'}
        if mode == 'missing':
            assert before['dags'] == []
            request('missing-task', dag + '/tasks/' + config['task_id'], expected=404)
            request('missing-create', dag + '/dag_runs', b'{"conf":{"message":"ordinary"}}', expected=404, json_data=True)
        else:
            task = json.loads(request('task', dag + '/tasks/' + config['task_id']))
            patched = mode in ['fixed', 'patched']
            assert ('dag_run' in task['env']) == patched
            assert len(before['dags']) == 1 and before['dags'][0]['is_paused'] is True
            request('unpause', dag + '/paused/false')
            proof['ordinary'] = trigger('ordinary', 'ordinary-' + nonce)
            if phase == 'before':
                marker = '/tmp/module-target-airflow-native-' + nonce
                assert file_state('marker-before', marker)['exists'] is False
                code = "import pathlib;pathlib.Path(" + repr(marker) + ").write_text(" + repr(nonce) + ")"
                proof['injected'] = trigger('injected', '\"; python -c ' + shlex.quote(code) + ';#')
                observed = file_state('injected-file', marker)
                expected = {'exists': False, 'uid': None, 'base64': None} if patched else {'exists': True, 'uid': config['uid'], 'base64': base64.b64encode(nonce.encode()).decode()}
                assert observed == expected
                proof['command_proof'] = observed
                command('remove-proof', 'rm', '-f', marker)
                assert file_state('marker-removed', marker)['exists'] is False
    state = control('completed-runs')
    proof['completed'] = state
    expected_count = 0 if mode in ['denied', 'missing'] else (2 if phase == 'before' else 1)
    assert len(state['runs']) == expected_count
    assert all(run['run_id'].startswith('module-target-' + nonce + '-') and run['state'] == 'success' for run in state['runs'])
    assert len(state['tasks']) == expected_count * 2 and all(task['state'] == 'success' for task in state['tasks'])
    after = control('reset', {'runs': state['runs'], 'paused': True})
    assert canonical(after) == canonical(before)
    proof['snapshot'] = canonical(after)
    proof['status'] = 'passed'
except BaseException as error:
    proof['status'] = 'failed'
    proof['error'] = {'type': type(error).__name__, 'message': str(error)}
    raise
finally:
    (Path(runtime['artifacts']) / ('native-airflow-' + phase + '.json')).write_text(json.dumps(proof, indent=2) + '\n')
print('Native Airflow controls passed: ' + phase + ' ' + mode)
