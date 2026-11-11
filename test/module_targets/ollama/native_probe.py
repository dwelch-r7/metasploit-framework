"""Genuine Ollama CLI/model/inference controls; never manufacture API responses."""
import base64
import hashlib
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request

ROOT = 'http://127.0.0.1:11434'
MODEL = Path('/lab/smollm-135m.gguf')
DIGEST = 'eb2c714d40d4b35ba4b8ee98475a06d51d8080a17d2d2a75a23665985c739b94'
RUNNING = 'lab-running:cpu'
INSTALLED = 'lab-installed:bare'
SYSTEM = 'Module target single-line system prompt'
MULTILINE = 'Module target first system line\nModule target second system line'
HTTP = []
CLI = []
RUNNER_OPTIONS = {'num_ctx': 128, 'num_batch': 16, 'num_thread': 1}


def request(base, path, payload=None, auth=False, expected=200, timeout=15):
    body = None if payload is None else json.dumps(payload).encode()
    headers = {} if body is None else {'Content-Type': 'application/json'}
    if auth:
        headers['Authorization'] = 'Basic ' + base64.b64encode(b'laboperator:module-target-password').decode()
    req = urllib.request.Request(base + path, data=body, headers=headers)
    try:
        response = urllib.request.urlopen(req, timeout=timeout)
    except urllib.error.HTTPError as error:
        response = error
    with response:
        raw = response.read()
        code = response.code
    HTTP.append({'base': base, 'path': path, 'payload': payload, 'authenticated': auth, 'code': code, 'body_base64': base64.b64encode(raw).decode()})
    assert code == expected, (base, path, code, raw[:300])
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        return raw.decode()


def cli(*arguments):
    env = os.environ.copy()
    env['OLLAMA_HOST'] = '127.0.0.1:11434'
    result = subprocess.run(['/bin/ollama', *arguments], capture_output=True, text=True, env=env, timeout=60)
    CLI.append({'argv': ['/bin/ollama', *arguments], 'exitstatus': result.returncode, 'stdout': result.stdout, 'stderr': result.stderr})
    assert result.returncode == 0, CLI[-1]
    return result.stdout


def until(function, timeout=15):
    deadline = time.monotonic() + timeout
    while True:
        if value := function():
            return value
        if time.monotonic() >= deadline:
            raise TimeoutError('Native Ollama state did not converge')
        time.sleep(0.2)


def show(name, base=ROOT, auth=False, expected=200):
    return request(base, '/api/show', {'name': name}, auth=auth, expected=expected)


def catalog():
    return request(ROOT, '/api/tags')['models']


def running():
    return request(ROOT, '/api/ps')['models']


def unload():
    for model in running():
        value = request(ROOT, '/api/generate', {'model': model['name'], 'keep_alive': 0, 'stream': False, 'options': RUNNER_OPTIONS}, timeout=60)
        assert value['done'] is True
    until(lambda: not running())


def create(name, system=None, temperature=None):
    content = 'FROM ' + str(MODEL) + '\n'
    if system is not None:
        content += 'SYSTEM """' + system + '"""\n'
    if temperature is not None:
        content += 'PARAMETER temperature ' + str(temperature) + '\n'
    file = Path('/runtime') / ('Modelfile-' + name.split(':')[0])
    file.write_text(content)
    cli('create', name, '-f', str(file))


def generate():
    value = request(ROOT, '/api/generate', {'model': RUNNING, 'prompt': 'Hello', 'raw': True, 'stream': False, 'keep_alive': -1,
                    'options': dict(RUNNER_OPTIONS, num_predict=1, seed=7, temperature=0)}, timeout=90)
    assert value['done'] is True and value['eval_count'] == 1 and value['response'], value
    until(lambda: len(running()) == 1 and running()[0]['name'] == RUNNING)
    return value


def validate(state):
    models = catalog()
    active = running()
    wanted = set() if state == 'empty' else {RUNNING, INSTALLED}
    assert {m['name'] for m in models} == wanted
    assert {m['name'] for m in active} == ({RUNNING} if state in {'baseline', 'multiline'} else set())
    details = {}
    for model in models:
        value = show(model['name'])
        assert value['details']['parameter_size'] and model['size'] > 0
        details[model['name']] = value
    if state != 'empty':
        expected_system = MULTILINE if state == 'multiline' else SYSTEM
        assert details[RUNNING]['system'] == expected_system
        assert '0.42' in details[RUNNING]['parameters']
        assert not details[INSTALLED].get('system') and not details[INSTALLED].get('parameters')
    return {'models': models, 'running': active, 'details': details}


def prepare(state):
    unload()
    known = {row['name'] for row in catalog()}
    assert known <= {RUNNING, INSTALLED}, known
    if state == 'empty':
        for name in sorted(known):
            cli('rm', name)
    else:
        # CLI imports real GGUF weights. No model/API metadata is handwritten.
        create(INSTALLED)
        create(RUNNING, MULTILINE if state == 'multiline' else SYSTEM, 0.42)
        if state in {'baseline', 'multiline'}:
            return generate()
    return None


def proxy_controls(snapshot):
    host = os.environ['MODULE_TARGET_PROXY_HOST']
    public = 'http://' + host + ':11800'
    denied = 'http://' + host + ':11801'
    guarded = 'http://' + host + ':11802'
    unrelated = 'http://' + host + ':80'
    for base, prefix, authenticated in [(public, '', False), (public, '/nested', False), (guarded, '', True)]:
        assert request(base, prefix + '/', auth=authenticated) == 'Ollama is running'
        assert {m['name'] for m in request(base, prefix + '/api/tags', auth=authenticated)['models']} == {RUNNING, INSTALLED}
        details = request(base, prefix + '/api/show', {'name': RUNNING}, auth=authenticated)
        assert details['system'] == SYSTEM
    assert request(denied, '/') == 'Ollama is running'
    assert len(request(denied, '/api/tags')['models']) == 2
    show(RUNNING, denied, expected=401)
    assert show(RUNNING, denied, auth=True)['system'] == SYSTEM
    request(guarded, '/', expected=401)
    assert request(unrelated, '/') != 'Ollama is running'
    request(unrelated, '/api/tags', expected=404)
    request(public, '/absent-base/', expected=404)
    with socket.socket() as connection:
        connection.settimeout(2)
        assert connection.connect_ex(('127.0.0.1', 11999)) != 0


phase, state = sys.argv[1:]
result = {'status': 'native_failed', 'phase': phase, 'state': state, 'framework_calls': 0, 'http': HTTP, 'cli': CLI, 'hostname': socket.gethostname()}
try:
    assert state in {'baseline', 'installed', 'empty', 'multiline'}
    assert hashlib.sha256(MODEL.read_bytes()).hexdigest() == DIGEST
    result['gguf_sha256'] = DIGEST
    def ready():
        try:
            return request(ROOT, '/api/version', timeout=3)['version'] == '0.1.48'
        except (urllib.error.URLError, TimeoutError):
            return False
    until(ready, 90)
    result['cli_version'] = cli('--version')
    assert '0.1.48' in result['cli_version']
    if phase in {'bootstrap', 'prepare'}:
        result['generation'] = prepare(state)
    if phase in {'before', 'after'}:
        result['generation'] = generate()
    result['snapshot'] = validate(state)
    if phase in {'before', 'after'}:
        proxy_controls(result['snapshot'])
    cgroup = Path('/sys/fs/cgroup')
    result['resources'] = {name: (cgroup / name).read_text() for name in ['memory.current', 'memory.peak', 'memory.events', 'pids.current', 'pids.events'] if (cgroup / name).is_file()}
    events = result['resources'].get('memory.events')
    if events:
        assert int(dict(line.split() for line in events.splitlines())['oom_kill']) == 0, events
    result['status'] = 'native_passed'
except Exception as error:
    result['error'] = type(error).__name__ + ': ' + str(error)
print(json.dumps(result))
sys.exit(0 if result['status'] == 'native_passed' else 1)
