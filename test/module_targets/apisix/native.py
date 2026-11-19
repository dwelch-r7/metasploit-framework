"""Stock APISIX prerequisites and exact command/route controls.

The numeric string.char command construction is independent of the owner's Lua
literal encoder. The distroless etcd image has no cat: its Docker Engine state
is recorded separately from the application's kernel resource counters.
"""
from pathlib import Path
import base64, errno, hashlib, json, os, shlex, socket, subprocess, sys, time, urllib.error, urllib.request
SOURCE_SHA256 = {'2.12.0': {'apisix/admin/routes.lua': '1b36066e02014b521b1c73b69867fad9a9fbb328f5b97dc6a92bfec916200440', 'apisix/plugins/batch-requests.lua': '2ec4ed50371c8835287fe3085e42b80b0c051a5b2820c055e34b5d008beb7fa3'}, '2.12.1': {'apisix/admin/routes.lua': '1b36066e02014b521b1c73b69867fad9a9fbb328f5b97dc6a92bfec916200440', 'apisix/plugins/batch-requests.lua': '39ff653f2cd9dcda83c42e925e420ba153f1f435c2c469305fee3bb0fbbb29b3'}}
runtime = json.loads(Path(sys.argv[1]).read_text())
op = sys.argv[2]
artifacts = Path(runtime['artifacts'])
kind = os.environ['APISIX_KIND']
version = os.environ['APISIX_VERSION']
origin = 'http://' + runtime['endpoints']['app']['host'] + ':' + str(runtime['endpoints']['app']['port'])
key = 'edd1c9f034335f136f87ad84b625c8f1'
state_path = artifacts / 'apisix-native-state.json'
execution_user = None
record = {'operation': op, 'kind': kind, 'version': version, 'checks': [], 'commands': [], 'http': []}

def check(name, passed):
    record['checks'].append({'name': name, 'passed': bool(passed)})
    if not passed:
        raise AssertionError(name)

def command(role, *args, required=True, timeout=25):
    user_options = ['--user', str(execution_user)] if role == 'app' and execution_user is not None else []
    argv = runtime['compose'] + ['exec', '-T', *user_options, role, *args]
    p = subprocess.run(argv, capture_output=True, timeout=timeout)
    record['commands'].append({'argv': argv, 'exit': p.returncode, 'stdout_base64': base64.b64encode(p.stdout).decode(), 'stderr': p.stderr.decode(errors='replace')})
    if required and p.returncode:
        raise RuntimeError(str(args) + ': ' + p.stderr.decode(errors='replace'))
    return p.stdout

def http(path, method='GET', document=None, local=False, token=key, outer_headers=None):
    data = json.dumps(document, ensure_ascii=False).encode() if document is not None else None
    if local:
        args = ['curl', '-sS', '--max-time', '10', '-X', method, '-H', 'X-API-KEY: ' + token, '-H', 'Content-Type: application/json', '-w', '\n%{http_code}']
        if data is not None:
            args += ['--data-binary', data.decode()]
        args += ['http://127.0.0.1:9080' + path]
        raw = command('app', *args)
        body, status = raw.rsplit(b'\n', 1)
        status = int(status)
        headers = {}
    else:
        headers = {'X-API-KEY': token, 'Content-Type': 'application/json'}
        headers.update(outer_headers or {})
        req = urllib.request.Request(origin + path, method=method, data=data, headers=headers)
        try:
            response = urllib.request.urlopen(req, timeout=12)
        except urllib.error.HTTPError as error:
            response = error
        body = response.read()
        status = response.code
        headers = dict(response.headers)
    name = 'apisix-http-' + hashlib.sha256(body).hexdigest() + '.bytes'
    (artifacts / name).write_bytes(body)
    record['http'].append({'path': path, 'method': method, 'local': local, 'token_role': 'default' if token == key else 'incorrect', 'request_base64': base64.b64encode(data).decode() if data is not None else None, 'status': status, 'headers': headers, 'body_file': name})
    try:
        document = json.loads(body)
    except (ValueError, UnicodeDecodeError):
        document = None
    return (status, document, body)

def api(path, method='GET', document=None, local=False, token=key):
    if local or kind == 'direct':
        return http(path, method, document, local, token)
    pipeline = {'method': method, 'path': path}
    if document is not None:
        pipeline['body'] = json.dumps(document, ensure_ascii=False)
    status, body, raw = http('/apisix/batch-requests', 'POST', {'headers': {'X-Real-IP': '127.0.0.1', 'X-API-KEY': token, 'Content-Type': 'application/json'}, 'pipeline': [pipeline]})
    check('batch-outer-200', status == 200)
    check('batch-exactly-one-inner-result', isinstance(body, list) and len(body) == 1)
    inner = body[0]
    encoded = inner.get('body', '').encode()
    try:
        decoded = json.loads(encoded)
    except ValueError:
        decoded = None
    return (inner['status'], decoded, encoded)

def inventory():
    rows = json.loads(command('database', '/usr/local/bin/etcdctl', 'get', '/apisix/routes/', '--prefix', '-w', 'json'))
    return sorted([{'key': base64.b64decode(row['key']).decode(), 'value': base64.b64decode(row['value']).decode()} for row in rows.get('kvs', [])], key=lambda row: row['key'])

def file_state(path):
    lines = command('app', 'sh', '-c', 'if [ -f "$1" ]; then stat -c "%u %s" "$1"; base64 "$1"; else printf "ABSENT\\n"; fi', 'native-file', path).decode().splitlines()
    if lines == ['ABSENT']:
        return {'exists': False}
    uid, size = map(int, lines[0].split())
    data = base64.b64decode(''.join(lines[1:]))
    check('file-size-correct', len(data) == size)
    return {'exists': True, 'uid': uid, 'base64': base64.b64encode(data).decode()}

def resources(phase):
    for role in ['app']:
        for name in ['memory.events', 'pids.events']:
            fields = dict((line.split() for line in command(role, 'cat', '/sys/fs/cgroup/' + name).decode().splitlines()))
            check(phase + '-' + role + '-' + name, all((int(fields.get(field, '0')) == 0 for field in ['oom', 'oom_kill', 'max'])))
    identifiers = subprocess.check_output(runtime['compose'] + ['ps', '-q', 'database'], text=True).split()
    check(phase + '-one-etcd-container', len(identifiers) == 1)
    row = json.loads(subprocess.check_output(['docker', 'inspect', identifiers[0]], text=True))[0]
    record.setdefault('database_engine_state', []).append({'phase': phase, 'id': row['Id'], 'state': row['State'], 'restart_count': row['RestartCount'], 'limits': {key: row['HostConfig'][key] for key in ['Memory', 'MemorySwap', 'PidsLimit', 'NanoCpus']}})
    check(phase + '-etcd-running-healthy-no-engine-oom', row['State']['Running'] and (not row['State']['OOMKilled']) and (row['RestartCount'] == 0) and (row['State']['Health']['Status'] == 'healthy'))

def proof(label, contents, shell=None, path=None):
    path = path or '/tmp/module-target-apisix-native-' + label
    route_id = 'native_' + label
    uri = '/module-target-apisix-native-' + label
    check('native-file-initially-absent-' + label, file_state(path) == {'exists': False})
    before = inventory()
    shell = shell or 'printf %s ' + shlex.quote(contents) + ' > ' + path
    lua = 'os.execute(string.char(' + ','.join(map(str, shell.encode())) + '))'
    local = kind == 'fixed'
    created = False
    try:
        data = {'uri': uri, 'upstream': {'type': 'roundrobin', 'nodes': {'127.0.0.1:1': 1}}, 'filter_func': 'function(vars) ' + lua + '; return true end'}
        if kind == 'fixed':
            status, body, _ = api('/apisix/admin/routes/' + route_id, 'PUT', data)
            check('patched-batch-refuses-route-' + label, status == 403)
            check('patched-batch-does-not-write-route-' + label, inventory() == before)
        status, body, _ = api('/apisix/admin/routes/' + route_id, 'PUT', data, local=local)
        created = status in [200, 201]
        check('native-filter-route-created-' + label, created)
        deadline = time.monotonic() + 12
        while True:
            status, body, _ = http(uri)
            value = file_state(path)
            if value.get('exists'):
                break
            if time.monotonic() >= deadline:
                raise TimeoutError('Native filter_func did not execute')
            time.sleep(0.15)
        uid = int(command('app', 'id', '-u', 'nobody').decode())
        check('native-exact-filter-command-' + label, value == {'exists': True, 'uid': uid, 'base64': base64.b64encode(contents.encode()).decode()})
        record.setdefault('proofs', []).append({'label': label, 'command': shell, 'file': value})
    finally:
        if created:
            status, body, _ = api('/apisix/admin/routes/' + route_id, 'DELETE', local=local)
            check('native-route-deleted-' + label, status == 200)
        command('app', 'rm', '-f', path)
        check('native-file-removed-' + label, file_state(path) == {'exists': False})
        check('native-route-inventory-restored-' + label, inventory() == before)

def initialize():
    resources('before')
    actual = command('app', 'apisix', 'version').decode().splitlines()[-1]
    check('stock-release', actual == version)
    record['identity'] = {'version': actual, 'tools': command('app', 'sh', '-c', 'for name in sh bash nc curl wget base64 php python python3; do printf "%s=" "$name"; command -v "$name" || true; done').decode(), 'processes': command('app', 'ps', '-o', 'pid,user,args').decode(), 'etcd': command('database', '/usr/local/bin/etcdctl', 'version').decode(), 'source_hashes': command('app', 'sh', '-c', 'sha256sum /usr/local/apisix/apisix/admin/routes.lua /usr/local/apisix/apisix/plugins/batch-requests.lua /usr/local/apisix/conf/config.yaml').decode()}
    actual_hashes = {line.split()[1]: line.split()[0] for line in record['identity']['source_hashes'].splitlines()}
    for path, expected in SOURCE_SHA256[version].items():
        check('stock-source-' + path, actual_hashes['/usr/local/apisix/' + path] == expected)
    check('fresh-route-inventory', inventory() == [{'key': '/apisix/routes/', 'value': 'init_dir'}])
    status, body, _ = http('/apisix/admin/routes')
    check('direct-admin-access-gate', status == (200 if kind in ['direct', 'open_batch'] else 403))
    status, body, _ = http('/apisix/batch-requests', 'POST')
    check('native-batch-plugin-gate', status == (404 if kind == 'direct' else 400))
    status, body, _ = api('/apisix/admin/routes')
    check('native-effective-admin-gate', status == (403 if kind == 'fixed' else 200))
    status, body, _ = api('/apisix/admin/routes', token='module-target-incorrect-token')
    check('native-incorrect-key-denied', status == (403 if kind == 'fixed' else 401))
    proof('first', 'native-apisix-first')
    proof('repeat', 'APISIX \'single\' "double" \\ $HOME ]] 雪😀\r\nLine\tEnd')
    resources('after')
    sentinel()
    state = {'identity': record['identity'], 'inventory': inventory(), 'kind': kind, 'version': version, 'uid': int(command('app', 'id', '-u', 'nobody').decode())}
    state_path.write_text(json.dumps(state, indent=2) + '\n')
    return state

def sentinel():
    check('before-sentinel-empty', inventory() == [{'key': '/apisix/routes/', 'value': 'init_dir'}])
    data = {'uri': '/module-target-apisix-sentinel', 'name': 'module-target-sentinel', 'upstream': {'type': 'roundrobin', 'nodes': {'127.0.0.1:1': 1}}}
    status, body, _ = api('/apisix/admin/routes/index', 'PUT', data, local=True)
    check('sentinel-created', status == 201)
    value = inventory()
    check('sentinel-is-only-route', len(value) == 2 and [row['key'] for row in value] == ['/apisix/routes/', '/apisix/routes/index'])
    return value

def audit():
    resources('audit')
    state = json.loads(state_path.read_text())
    values = inventory()
    check('audit-route-inventory-restored', values == state['inventory'])
    check('audit-stock-worker-uid-preserved', int(command('app', 'id', '-u', 'nobody').decode()) == state['uid'])
    check('audit-version-preserved', command('app', 'apisix', 'version').decode().splitlines()[-1] == state['version'])
    return {'inventory': values, 'state': state}

def refused_port():
    with socket.socket() as listener:
        listener.bind(('127.0.0.1', 0))
        port = listener.getsockname()[1]
    with socket.socket() as probe:
        probe.settimeout(2)
        result = probe.connect_ex(('127.0.0.1', port))
    check('actual-host-port-refused', result == errno.ECONNREFUSED)
    return {'port': port, 'errno': result, 'refused': True}

def api_ready():
    status, body, _ = api('/apisix/admin/routes')
    check('admin-api-responsive-during-session', status == 200 and isinstance(body, dict) and (body.get('action') == 'get') and (body.get('node', {}).get('dir') is True))
    return {'status': status, 'routes': body}

def main():
    try:
        result = {'initialize': initialize, 'api_ready': api_ready, 'tools': lambda: command('app', 'sh', '-c', 'for name in bash nc php python python3; do printf "%s=" "$name"; command -v "$name" || true; done').decode(), 'inventory': inventory, 'refused_port': refused_port, 'command': lambda: proof('command', base64.b64decode(sys.argv[5]).decode(), shell=sys.argv[3], path=sys.argv[4]), 'audit': audit, 'file': lambda: file_state(sys.argv[3]), 'remove': lambda: command('app', 'rm', '-f', sys.argv[3]).decode()}[op]()
        record.update(passed=True, result=result)
    except BaseException as error:
        record.update(passed=False, error=type(error).__name__ + ': ' + str(error))
        raise
    finally:
        destination = artifacts / ('apisix-native-' + op + '-' + str(time.time_ns()) + '.json')
        destination.write_text(json.dumps(record, indent=2, ensure_ascii=False) + '\n')
        print('APISIX_NATIVE=' + json.dumps({'passed': record['passed'], 'record': str(destination), 'result': record.get('result')}))
if __name__ == '__main__':
    main()
