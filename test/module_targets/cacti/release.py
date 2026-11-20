from pathlib import Path
import base64, hashlib, json, os, shlex, subprocess, sys, time, urllib.request, urllib.error, urllib.parse
runtime = json.loads(Path(sys.argv[1]).read_text())
artifacts = Path(runtime['artifacts'])
version = os.environ['CACTI_VERSION']
expect_exec = os.environ['CACTI_EXPECT_EXEC']
record = {'owner_qualified': False, 'version': version, 'checks': [], 'commands': [], 'http': [], 'execution': []}

def check(name, passed):
    record['checks'].append({'name': name, 'passed': bool(passed)})
    if not passed:
        raise AssertionError(name)

def command(role, *args):
    p = subprocess.run([*runtime['compose'], 'exec', '-T', role, *args], capture_output=True, timeout=90)
    record['commands'].append({'role': role, 'arguments': args, 'exit': p.returncode, 'stdout_base64': base64.b64encode(p.stdout).decode(), 'stderr': p.stderr.decode(errors='replace')})
    check('command-exit', p.returncode == 0)
    return p.stdout.decode()

def sql(query):
    return command('db', 'mysql', '-uroot', '-proot', '--batch', '--raw', '--skip-column-names', 'cacti', '-e', query)

def resources(phase):
    for role in ['app', 'db']:
        for name in ['memory.events', 'pids.events']:
            fields = dict((line.split() for line in command(role, 'cat', '/sys/fs/cgroup/' + name).splitlines()))
            check(phase + '-' + role + '-' + name, all((int(fields.get(key, '0')) == 0 for key in ['oom', 'oom_kill', 'max'])))

def file_state(path):
    lines = command('app', 'sh', '-c', 'if [ -f "$1" ]; then stat -c "%u %s" "$1"; base64 "$1"; else printf "ABSENT\\n"; fi', 'native-file', path).splitlines()
    if lines == ['ABSENT']:
        return {'exists': False}
    uid, size = map(int, lines[0].split())
    raw = base64.b64decode(''.join(lines[1:]))
    check('file-size', len(raw) == size)
    return {'exists': True, 'uid': uid, 'base64': base64.b64encode(raw).decode()}

def request(poller, local=False, forwarded=True, data_id=None):
    params = {'action': 'polldata', 'host_id': host, 'local_data_ids[0]': data_id or local_id, 'poller_id': poller}
    path = '/remote_agent.php?' + urllib.parse.urlencode(params)
    if local:
        php = '$context=stream_context_create(["http"=>["ignore_errors"=>true,"timeout"=>20]]);$body=file_get_contents($argv[1],false,$context);if($body===false){exit(1);}preg_match("~HTTP/[^ ]+ ([0-9]+)~",$http_response_header[0],$match);echo json_encode(["status"=>(int)$match[1],"body"=>base64_encode($body)]);'
        value = json.loads(command('app', 'php', '-r', php, 'http://127.0.0.1' + path))
        status = value['status']
        raw = base64.b64decode(value['body'])
    else:
        endpoint = runtime['endpoints']['app']
        origin = 'http://' + endpoint['host'] + ':' + str(endpoint['port'])
        req = urllib.request.Request(origin + path, headers={'X-Forwarded-For': '127.0.0.1'} if forwarded else {})
        try:
            response = urllib.request.urlopen(req, timeout=20)
        except urllib.error.HTTPError as error:
            response = error
        status = response.code
        raw = response.read()
    name = 'release-http-' + hashlib.sha256(raw).hexdigest() + '.bytes'
    (artifacts / name).write_bytes(raw)
    record['http'].append({'local': local, 'forwarded': forwarded, 'parameters': params, 'status': status, 'body_file': name})
    return (status, raw)
try:
    resources('before')
    source = json.loads(Path('test/module_targets/cacti/releases.json').read_text())[version]
    record['identity'] = command('app', 'sh', '-c', 'cat /etc/os-release; php -v; id www-data; sha256sum remote_agent.php lib/functions.php script_server.php')
    for path, expected in source['critical_sha256'].items():
        check('source-' + path, command('app', 'sha256sum', path).split()[0] == expected)
    check('actual-db-version', sql('SELECT cacti FROM version').strip() == version)
    record['install'] = sql("SELECT name,value FROM settings WHERE name IN ('install_step','install_error','install_progress','install_version')")
    check('installer-complete', 'install_step\t98' in record['install'] and 'install_progress\t100' in record['install'])
    templates = command('app', 'php', 'cli/add_graphs.php', '--list-graph-templates')
    template = next((line.split('\t')[0] for line in templates.splitlines() if line.endswith('\tDevice - Uptime')))
    record['graph'] = command('app', 'php', 'cli/add_graphs.php', '--host-id=1', '--graph-type=cg', '--graph-template-id=' + template)
    record['poller'] = sql('SELECT host_id,local_data_id,action,rrd_name FROM poller_item WHERE action=2')
    row = record['poller'].splitlines()[0].split('\t')
    host, local_id = row[:2]
    check('actual-action2', row[2] == '2')
    uid = int(command('app', 'id', '-u', 'www-data').strip())
    status, body = request('1', local=True)
    check('local-legitimate-data', status == 200 and isinstance(json.loads(body), list) and bool(json.loads(body)))
    status, body = request('1')
    record['public_authorized'] = status == 200 and body.lstrip().startswith(b'[')
    status, body = request('1', forwarded=False)
    check('nonpoller-denied', b'not authorized' in body.lower())
    status, body = request('1', local=True, data_id='999999')
    check('missing-local-id-empty', json.loads(body) == [])
    for transport in ['local', 'public']:
        for label in ['first', 'repeat']:
            path = '/tmp/module-target-cacti-' + transport + '-' + label
            contents = 'cacti-' + version + '-' + transport + '-' + label
            check('marker-absent', file_state(path) == {'exists': False})
            shell = 'printf %s ' + shlex.quote(contents) + ' >> ' + path
            try:
                status, body = request('0$(' + shell + ')', local=transport == 'local')
                actual = file_state(path)
                if actual['exists']:
                    check('exact-marker-and-user', actual == {'exists': True, 'uid': uid, 'base64': base64.b64encode(contents.encode()).decode()})
                if expect_exec == 'false':
                    check('fixed-refuses-command', actual == {'exists': False})
                elif expect_exec == 'true':
                    check('vulnerable-executes-command', actual['exists'])
                record['execution'].append({'transport': transport, 'label': label, 'status': status, 'file': actual})
            finally:
                command('app', 'rm', '-f', path)
                check('marker-cleaned', file_state(path) == {'exists': False})
    resources('after')
    record['passed'] = True
finally:
    (artifacts / 'cacti-release.json').write_text(json.dumps(record, indent=2) + '\n')
    print(json.dumps(record))
