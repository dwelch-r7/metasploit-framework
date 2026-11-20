from pathlib import Path
import base64, hashlib, json, subprocess, sys, urllib.request
runtime = json.loads(Path(sys.argv[1]).read_text())
artifacts = Path(runtime['artifacts'])
record = {'commands': [], 'owner_qualified': False}

def command(role, *arguments):
    p = subprocess.run([*runtime['compose'], 'exec', '-T', role, *arguments], capture_output=True, timeout=90)
    record['commands'].append({'role': role, 'arguments': arguments, 'exit': p.returncode, 'stdout_base64': base64.b64encode(p.stdout).decode(), 'stderr': p.stderr.decode(errors='replace')})
    assert p.returncode == 0, p.stderr
    return p.stdout.decode()
try:
    record['identity'] = command('app', 'sh', '-c', 'cat /etc/os-release; php -v; id www-data; sha256sum remote_agent.php lib/functions.php script_server.php; ps -eo pid,ppid,user,args')
    record['database'] = command('db', 'mysql', '-uroot', '-proot', '--batch', '--raw', 'cacti', '-e', "SELECT VERSION(); SELECT * FROM version; SELECT name,value FROM settings WHERE name LIKE 'install%' OR name='path_php_binary'; SELECT id,hostname FROM poller; SELECT id,description,hostname FROM host; SELECT host_id,local_data_id,action,rrd_name,arg1 FROM poller_item;")
    record['templates'] = command('app', 'php', 'cli/add_graphs.php', '--list-graph-templates')
    endpoint = runtime['endpoints']['app']
    response = urllib.request.urlopen('http://' + endpoint['host'] + ':' + str(endpoint['port']) + '/', timeout=10)
    body = response.read()
    (artifacts / 'native-index.bytes').write_bytes(body)
    record['http'] = {'status': response.code, 'url': response.url, 'sha256': hashlib.sha256(body).hexdigest()}
    assert response.code == 200 and b'<title>Login to Cacti' in body
    templates = [line.split('\t', 1) for line in record['templates'].splitlines() if '\t' in line]
    identifier = next((key for key, name in templates if name == 'Device - Uptime'))
    record['graph_create'] = command('app', 'php', 'cli/add_graphs.php', '--host-id=1', '--graph-type=cg', '--graph-template-id=' + identifier)
    record['poller_after'] = command('db', 'mysql', '-uroot', '-proot', '--batch', '--raw', '--skip-column-names', 'cacti', '-e', 'SELECT host_id,local_data_id,action,rrd_name,arg1 FROM poller_item WHERE action=2')
    rows = [line.split('\t') for line in record['poller_after'].splitlines()]
    assert rows and all((row[2] == '2' for row in rows))
    host_id, local_id = rows[0][:2]
    record['selected'] = {'host_id': host_id, 'local_data_id': local_id, 'rrd_name': rows[0][3]}
    import urllib.parse
    origin = 'http://' + endpoint['host'] + ':' + str(endpoint['port'])

    def polldata(poller, forwarded=True, local=local_id):
        args = {'action': 'polldata', 'host_id': host_id, 'local_data_ids[0]': local, 'poller_id': poller}
        headers = {'X-Forwarded-For': '127.0.0.1'} if forwarded else {}
        request = urllib.request.Request(origin + '/remote_agent.php?' + urllib.parse.urlencode(args), headers=headers)
        response = urllib.request.urlopen(request, timeout=20)
        raw = response.read()
        name = 'native-polldata-' + hashlib.sha256(raw).hexdigest() + '.bytes'
        (artifacts / name).write_bytes(raw)
        record.setdefault('polldata', []).append({'arguments': args, 'forwarded': forwarded, 'status': response.code, 'body_file': name})
        return raw
    baseline = polldata('1')
    record['polldata_baseline'] = json.loads(baseline)
    assert record['polldata_baseline']
    unauthorized = polldata('1', forwarded=False)
    assert b'not authorized' in unauthorized.lower()
    assert json.loads(polldata('1', local='999999')) == []
    path = '/tmp/module-target-cacti-native-proof'
    expected = 'native-cacti-once'
    record['file_absent'] = command('app', 'sh', '-c', '[ ! -e "$1" ]', 'native-path', path)
    shell = 'printf %s ' + expected + ' >> ' + path
    polldata('0$(' + shell + ')')
    record['marker'] = command('app', 'sh', '-c', 'stat -c "%u %s" "$1"; base64 "$1"', 'native-path', path)
    uid_size, encoded = record['marker'].splitlines()
    assert uid_size == '33 ' + str(len(expected)) and base64.b64decode(encoded) == expected.encode()
    command('app', 'rm', '-f', path)
    command('app', 'sh', '-c', '[ ! -e "$1" ]', 'native-path', path)
    record['passed'] = True
finally:
    (artifacts / 'cacti-bootstrap.json').write_text(json.dumps(record, indent=2) + '\n')
    print(json.dumps(record))
