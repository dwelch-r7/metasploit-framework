"""Independent stock-Kong controls; no module helpers or generated Lua literals."""
from pathlib import Path
import base64
import hashlib
import json
import os
import shlex
import subprocess
import sys
import time
import urllib.error
import urllib.request

runtime = json.loads(Path(sys.argv[1]).read_text())
operation = sys.argv[2]
artifacts = Path(runtime['artifacts'])
state_path = artifacts / 'kong-native-state.json'
endpoint = runtime['endpoints']['app']
admin = 'http://' + endpoint['host'] + ':' + str(endpoint['port'])
enabled = os.environ['KONG_EXPECT_PLUGIN'] == 'true'
record = {'operation': operation, 'enabled': enabled, 'checks': [], 'commands': [], 'http': []}


def check(name, passed):
    record['checks'].append({'name': name, 'passed': bool(passed)})
    if not passed:
        raise AssertionError(name)


def command(role, *arguments, timeout=25, required=True):
    argv = runtime['compose'] + ['exec', '-T', role, *arguments]
    result = subprocess.run(argv, capture_output=True, timeout=timeout)
    record['commands'].append({'argv': argv, 'exit': result.returncode, 'stdout_base64': base64.b64encode(result.stdout).decode(), 'stderr': result.stderr.decode(errors='replace')})
    if required and result.returncode:
        raise RuntimeError('Native command failed: ' + repr(arguments) + ': ' + result.stderr.decode(errors='replace'))
    return result.stdout


def request(label, path, method='GET', document=None, public=False):
    if public:
        result = subprocess.run(runtime['compose'] + ['port', 'app', '8000'], capture_output=True, text=True, timeout=15, check=True)
        binding = result.stdout.strip()
        check('public-port-is-loopback', binding.startswith('127.0.0.1:') and binding.count(':') == 1)
        origin = 'http://' + binding
    else:
        origin = admin
    data = json.dumps(document, ensure_ascii=False).encode() if document is not None else None
    req = urllib.request.Request(origin + path, data=data, method=method, headers={'Content-Type': 'application/json'})
    try:
        response = urllib.request.urlopen(req, timeout=15)
    except urllib.error.HTTPError as error:
        response = error
    body = response.read()
    digest = hashlib.sha256(body).hexdigest()
    filename = 'kong-native-' + label + '-' + digest + '.bytes'
    (artifacts / filename).write_bytes(body)
    record['http'].append({'label': label, 'url': origin + path, 'method': method, 'request_base64': base64.b64encode(data).decode() if data else None, 'status': response.code, 'body_file': filename, 'body_sha256': digest})
    return response.code, json.loads(body) if body else None


def inventory():
    result = {}
    for kind in ['routes', 'plugins', 'services']:
        status, body = request('inventory-' + kind, '/' + kind)
        check('list-' + kind, status == 200 and body.get('next') is None)
        result[kind] = sorted(body['data'], key=lambda row: row['id'])
    return result


def resources(phase):
    for role in ['app', 'database']:
        for name in ['memory.events', 'pids.events']:
            fields = dict(line.split() for line in command(role, 'cat', '/sys/fs/cgroup/' + name).decode().splitlines())
            check(phase + '-' + role + '-' + name, all(int(fields.get(key, '0')) == 0 for key in ['oom', 'oom_kill', 'max']))


def file_state(path):
    output = command('app', 'sh', '-c', 'if [ -f "$1" ]; then stat -c "%u %s" "$1"; base64 "$1"; else printf "ABSENT\\n"; fi', 'kong-native-file', path).decode().splitlines()
    if output == ['ABSENT']:
        return {'exists': False}
    uid, size = map(int, output[0].split())
    contents = base64.b64decode(''.join(output[1:]))
    check('file-size-matches-bytes', len(contents) == size)
    return {'exists': True, 'uid': uid, 'base64': base64.b64encode(contents).decode()}


def application():
    status, body = request('application', '/')
    check('real-admin-api', status == 200 and body['tagline'].lower() == 'welcome to kong')
    check('real-release', body['version'] == '2.1.4' and command('app', 'kong', 'version').decode().strip() == '2.1.4')
    check('real-postgres-storage', body['configuration']['database'] == 'postgres')
    check('native-plugin-configuration', body['plugins']['available_on_server'].get('pre-function', False) == enabled)
    identity = {'uid': int(command('app', 'id', '-u').decode()), 'version': body['version']}
    identity['sources'] = command('app', 'sh', '-c', 'find /usr/local/share/lua/5.1/kong/plugins/pre-function -type f -exec sha256sum {} \\; | sort').decode()
    check('real-plugin-source-present', 'handler.lua' in identity['sources'])
    record['stock_tools'] = command('app', 'sh', '-c', 'for tool in sh bash nc curl wget base64 python3; do printf "%s=" "$tool"; command -v "$tool" || true; done').decode()
    record['database_version'] = command('database', 'psql', '-U', 'kong', '-d', 'kong', '-Atc', 'SELECT version()').decode()
    record['application'] = body
    return identity


def proof(label, contents, shell=None, path=None):
    name = 'module-native-' + str(os.getpid()) + '-' + label
    path = path or '/tmp/' + name
    baseline = inventory()
    check('fresh-proof-file-' + label, file_state(path) == {'exists': False})
    shell = shell or 'printf %s ' + shlex.quote(contents) + ' > ' + shlex.quote(path)
    # Decimal byte construction deliberately differs from the owner's Lua quoting.
    lua = 'os.execute(string.char(' + ','.join(map(str, shell.encode())) + '))'
    created = False
    try:
        status, route = request('create-' + label, '/routes', method='POST', document={'name': name, 'paths': ['/' + name]})
        created = status == 201
        check('native-route-created-' + label, created and route['name'] == name)
        status, plugin = request('plugin-' + label, '/routes/' + name + '/plugins', method='POST', document={'name': 'pre-function', 'config': {'access': [lua]}})
        if enabled:
            check('native-plugin-created-' + label, status == 201 and plugin['route']['id'] == route['id'])
            deadline = time.monotonic() + 15
            while True:
                status, body = request('trigger-' + label, '/' + name, public=True)
                value = file_state(path)
                if value.get('exists'):
                    break
                if time.monotonic() >= deadline:
                    raise TimeoutError('Native route did not execute')
                time.sleep(0.2)
            check('native-proxy-status-' + label, status == 503)
            expected = {'exists': True, 'uid': int(command('app', 'id', '-u').decode()), 'base64': base64.b64encode(contents.encode()).decode()}
            record.setdefault('proofs', []).append({'label': label, 'command': shell, 'path': path, 'file': value})
            check('exact-native-command-bytes-' + label, value == expected)
        else:
            check('native-disabled-plugin-rejection-' + label, status == 400 and 'not enabled' in json.dumps(plugin))
            check('native-disabled-proof-absent-' + label, file_state(path) == {'exists': False})
    finally:
        if created:
            status, body = request('delete-' + label, '/routes/' + name, method='DELETE')
            check('native-route-deleted-' + label, status == 204)
        command('app', 'rm', '-f', path)
        check('native-proof-removed-' + label, file_state(path) == {'exists': False})
        check('native-inventory-restored-' + label, inventory() == baseline)


def initialize():
    resources('before')
    identity = application()
    before = inventory()
    check('fresh-entity-inventory', before == {'routes': [], 'plugins': [], 'services': []})
    proof('first', 'native-kong-first')
    proof('repeat', 'Kong \'single\' "double" \\ $HOME ${literal} $(printf nested) ]] 雪😀\nLine\tEnd')
    check('application-identity-preserved', application() == identity)
    check('entities-restored-after-native-repeats', inventory() == before)
    resources('after')
    state = {'identity': identity, 'inventory': before, 'enabled': enabled}
    state_path.write_text(json.dumps(state, indent=2) + '\n')
    return state


def audit():
    state = json.loads(state_path.read_text())
    check('identity-preserved', application() == state['identity'])
    check('inventory-restored', inventory() == state['inventory'])
    resources('audit')
    return state


def main():
    try:
        actions = {'initialize': initialize, 'audit': audit,
                   'command': lambda: proof('command', base64.b64decode(sys.argv[5]).decode(), shell=sys.argv[3], path=sys.argv[4]),
                   'file': lambda: file_state(sys.argv[3])}
        record['result'] = actions[operation]()
        record['passed'] = True
    except BaseException as error:
        record['passed'] = False
        record['error'] = type(error).__name__ + ': ' + str(error)
        raise
    finally:
        destination = artifacts / ('kong-native-' + operation + '-' + str(time.time_ns()) + '.json')
        destination.write_text(json.dumps(record, indent=2, ensure_ascii=False) + '\n')
        print('KONG_NATIVE=' + json.dumps({'passed': record['passed'], 'record': str(destination), 'checks': len(record['checks']), 'result': record.get('result')}))


if __name__ == '__main__':
    main()
