from pathlib import Path
import base64, hashlib, json, subprocess, sys, time, urllib.request, urllib.error, urllib.parse
runtime = json.loads(Path(sys.argv[1]).read_text())
op = sys.argv[2]
artifacts = Path(runtime['artifacts'])
state_path = artifacts / 'cacti-native-state.json'
execution_user = None
record = {'operation': op, 'checks': [], 'commands': [], 'http': []}

def check(name, passed):
    record['checks'].append({'name': name, 'passed': bool(passed)})
    if not passed:
        raise AssertionError(name)

def command(role, *args, required=True, timeout=30):
    user = ['--user', str(execution_user)] if role == 'app' and execution_user is not None else []
    argv = [*runtime['compose'], 'exec', '-T', *user, role, *args]
    p = subprocess.run(argv, capture_output=True, timeout=timeout)
    record['commands'].append({'argv': argv, 'exit': p.returncode, 'stdout_base64': base64.b64encode(p.stdout).decode(), 'stderr': p.stderr.decode(errors='replace')})
    if required:
        check('native-command-exit', p.returncode == 0)
    return p.stdout

def sql(query):
    return command('db', 'mysql', '-uroot', '-proot', '--batch', '--raw', '--skip-column-names', 'cacti', '-e', query).decode()

def inventory():
    return sql('SELECT JSON_ARRAY(host_id,local_data_id,action,rrd_name,arg1) FROM poller_item ORDER BY host_id,local_data_id,rrd_name')

def resources(phase):
    for role in ['app', 'db']:
        for filename in ['memory.events', 'pids.events']:
            fields = dict((line.split() for line in command(role, 'cat', '/sys/fs/cgroup/' + filename).decode().splitlines()))
            check(phase + '-' + role + '-' + filename, all((int(fields.get(k, '0')) == 0 for k in ['oom', 'oom_kill', 'max'])))

def file_state(path):
    lines = command('app', 'sh', '-c', 'if [ -f "$1" ]; then stat -c "%u %s" "$1"; base64 "$1"; else printf "ABSENT\\n"; fi', 'native-file', path).decode().splitlines()
    if lines == ['ABSENT']:
        return {'exists': False}
    uid, size = map(int, lines[0].split())
    raw = base64.b64decode(''.join(lines[1:]))
    check('native-file-size', len(raw) == size)
    return {'exists': True, 'uid': uid, 'base64': base64.b64encode(raw).decode()}

def http(poller, host_id, local_id, forwarded=True):
    endpoint = runtime['endpoints']['app']
    origin = 'http://' + endpoint['host'] + ':' + str(endpoint['port'])
    params = {'action': 'polldata', 'host_id': host_id, 'local_data_ids[0]': local_id, 'poller_id': poller}
    headers = {'X-Forwarded-For': '127.0.0.1'} if forwarded else {}
    req = urllib.request.Request(origin + '/remote_agent.php?' + urllib.parse.urlencode(params), headers=headers)
    try:
        response = urllib.request.urlopen(req, timeout=20)
    except urllib.error.HTTPError as error:
        response = error
    raw = response.read()
    name = 'cacti-http-' + hashlib.sha256(raw).hexdigest() + '.bytes'
    (artifacts / name).write_bytes(raw)
    record['http'].append({'parameters': params, 'headers': headers, 'status': response.code, 'body_file': name})
    return (response.code, raw)

def initialize():
    resources('before-initialize')
    p = subprocess.run(['python3', 'test/module_targets/cacti/bootstrap.py', sys.argv[1]], capture_output=True, text=True, timeout=150)
    record['bootstrap'] = {'exit': p.returncode, 'stdout': p.stdout, 'stderr': p.stderr}
    check('genuine-bootstrap-controls', p.returncode == 0)
    boot = json.loads((artifacts / 'cacti-bootstrap.json').read_text())
    sources = json.loads(Path('test/module_targets/cacti/sources.json').read_text())
    for path in ['remote_agent.php', 'lib/functions.php']:
        expected = next((row['sha256'] for row in sources if row.get('repository') == 'Cacti/cacti' and row['path'] == path))
        check('stock-source-' + path, command('app', 'sha256sum', path).decode().split()[0] == expected)
    version = sql('SELECT cacti FROM version').strip()
    check('actual-version', version == '1.2.22')
    capabilities = {}
    for binary in ['bash', 'php', 'curl', 'wget', 'base64', 'nc', 'ncat']:
        raw = command('app', 'sh', '-c', 'command -v "$1"', 'native-runtime', binary, required=False)
        capabilities[binary] = {'path': raw.decode().strip(), 'exit': record['commands'][-1]['exit']}
    result = {'selected': boot['selected'], 'uid': int(command('app', 'id', '-u', 'www-data').decode()), 'inventory': inventory(), 'version': version, 'capabilities': capabilities}
    state_path.write_text(json.dumps(result, indent=2) + '\n')
    resources('after-initialize')
    return result

def proof(shell, path, expected):
    state = json.loads(state_path.read_text())
    check('before-proof-absent', file_state(path) == {'exists': False})
    resources('before-proof')
    try:
        status, raw = http('0$(' + shell + ')', state['selected']['host_id'], state['selected']['local_data_id'])
        check('native-proof-http', status == 200)
        actual = file_state(path)
        check('native-exact-command', actual == {'exists': True, 'uid': state['uid'], 'base64': expected})
        record['proof'] = {'command_base64': base64.b64encode(shell.encode()).decode(), 'file': actual}
        return record['proof']
    finally:
        command('app', 'rm', '-f', path)
        check('proof-removed', file_state(path) == {'exists': False})
        check('proof-preserves-poller', inventory() == state['inventory'])
        resources('after-proof')

def audit():
    state = json.loads(state_path.read_text())
    check('owner-preserves-poller', inventory() == state['inventory'])
    resources('audit')
    return {'inventory': state['inventory']}

def main():
    try:
        result = {'initialize': initialize, 'audit': audit, 'file': lambda: file_state(sys.argv[3]), 'remove': lambda: command('app', 'rm', '-f', sys.argv[3]).decode(), 'proof': lambda: proof(sys.argv[3], sys.argv[4], sys.argv[5])}[op]()
        record.update(passed=True, result=result)
    except BaseException as error:
        record.update(passed=False, error=type(error).__name__ + ': ' + str(error))
        raise
    finally:
        name = 'cacti-native-' + op + '-' + str(time.time_ns()) + '.json'
        (artifacts / name).write_text(json.dumps(record, indent=2) + '\n')
        print('CACTI_NATIVE=' + json.dumps({'passed': record['passed'], 'record': name, 'result': record.get('result')}))
if __name__ == '__main__':
    main()
