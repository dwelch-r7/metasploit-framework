"""Independent genuine single-version sampling and refusal/execution controls."""
import base64
import json
import os
from pathlib import Path
import secrets
import sys

sys.dont_write_bytecode = True
from native_adapter import SingleDruid

role = os.environ['DRUID_SINGLE_ROLE']
assert role in ['affected', 'fixed']
version = {'affected': '0.20.0', 'fixed': '0.20.1'}[role]
runtime = json.loads(Path(os.environ['MODULE_TARGET_RUNTIME']).read_text())
client = SingleDruid(runtime)
marker = '/tmp/module-target-druid-single-native'
names = [name + '-' + secrets.token_hex(6) for name in ['first', 'second', 'third']]
data = '\n'.join(json.dumps({'time': '2026-11-10T00:00:00Z', 'name': name, 'value': number}) for number, name in enumerate(names))
# The sealed pair probe runs at import time; these small independent sampler
# bodies are kept here so existing nineteen-case inputs need not be changed.
sample = {'type': 'index', 'spec': {'dataSchema': {'dataSource': 'module_native_single', 'timestampSpec': {'column': 'time', 'format': 'iso'}, 'dimensionsSpec': {'dimensions': ['name', 'value']}}, 'ioConfig': {'type': 'index', 'inputSource': {'type': 'inline', 'data': data}, 'inputFormat': {'type': 'json'}}}, 'samplerConfig': {'numRows': 3, 'timeoutMs': 3000}}
status = client.request('/app/', 'status')
assert status['status'] == 200 and json.loads(status['response'])['version'] == version
assert json.loads(client.request('/app/', 'status/health')['response']) is True
assert json.loads(client.request('/app/', 'druid/indexer/v1/isLeader')['response']) == {'leader': True}
ordinary = client.request('/app/', 'druid/indexer/v1/sampler', sample)
rows = json.loads(ordinary['response'])
assert ordinary['status'] == 200 and rows['numRowsRead'] == rows['numRowsIndexed'] == 3
assert [row['parsed']['name'] for row in rows['data']] == names
request_bytes = bytes.fromhex(ordinary['request_bytes_hex'])
identity = client.cli('app', 'id')['stdout']
java = client.cli('app', 'java', '-version')
config = client.cli('app', 'cat', '/tmp/conf/druid/cluster/master/coordinator-overlord/runtime.properties')['stdout']
assert 'druid.javascript.enabled=false' in config
jars = client.cli('app', 'sh', '-c', 'sha256sum /opt/druid/lib/druid-*.jar /opt/druid/lib/rhino-*.jar')['stdout']
processes = client.cli('app', 'ps', '-o', 'pid,ppid,args')['stdout']
assert '-Xmx384m' in processes and '-XX:MaxDirectMemorySize=128m' in processes and '-XX:ActiveProcessorCount=1' in processes
sql = client.cli('metadata', 'env', 'PGPASSWORD=module-target-druid-metadata-password', 'psql', '-h', '127.0.0.1', '-U', 'druid', '-d', 'druid', '-Atc', "SELECT tablename FROM pg_tables WHERE schemaname='public' ORDER BY tablename")['stdout']
assert 'module_single_segments' in sql
for route, auth, expected in [('/auth/', None, 401), ('/auth/', ('admin', 'wrong'), 401), ('/auth/', ('admin', 'module-target-druid-password'), 200), ('/auth/', ('viewer', 'module-target-viewer-password'), 200), ('/denied/', ('viewer', 'module-target-viewer-password'), 401), ('/denied/', ('admin', 'module-target-druid-password'), 200), ('/prefix/', None, 200), ('/', None, 200), ('/app/no-druid/', None, 404)]:
    row = client.request(route, '' if route == '/' else 'status', auth=auth)
    assert row['status'] == expected, row
    if expected == 200 and route != '/':
        assert json.loads(row['response'])['version'] == version
assert '<html>' in client.requests[-2]['response'].lower()
for iteration in range(2):
    for injected in [False, True]:
        client.cli('app', 'test', '!', '-e', marker)
        body = json.loads(json.dumps(sample))
        io = body['spec']['ioConfig']
        io['firehose'] = io.pop('inputSource')
        io.pop('inputFormat')
        schema = body['spec']['dataSchema']
        parse = {'format': 'javascript', 'timestampSpec': schema.pop('timestampSpec'), 'dimensionsSpec': schema.pop('dimensionsSpec')}
        command = "printf '%s' 'Native Druid: real execution' > " + marker
        parse['function'] = 'function(line){var a=java.lang.reflect.Array.newInstance(java.lang.String,3);a[0]="/bin/sh";a[1]="-c";a[2]=' + json.dumps(command) + ';var p=java.lang.Runtime.getRuntime().exec(a);p.waitFor();return {time:"2026-11-10T00:00:00Z",name:"native",value:p.exitValue()};}'
        if injected:
            parse[''] = {'enabled': True}
        schema['parser'] = {'type': 'string', 'parseSpec': parse}
        row = client.request('/app/', 'druid/indexer/v1/sampler', body)
        if role == 'affected' and injected:
            assert row['status'] == 200, row
            assert client.cli('app', 'cat', marker)['stdout'] == 'Native Druid: real execution'
            assert client.cli('app', 'stat', '-c', '%u:%g', marker)['stdout'].strip() == '1000:1000'
            client.cli('app', 'rm', '--', marker)
        else:
            assert row['status'] == 400 and 'JavaScript is disabled' in row['response'], row
        client.cli('app', 'test', '!', '-e', marker)
proof = {'role': role, 'version': version, 'ordinary_rows': rows, 'expected_names': names, 'sample_request_base64': base64.b64encode(request_bytes).decode(), 'identity': identity, 'java': java, 'jars': jars, 'actual_processes': processes, 'counts': {'commands': len(client.commands), 'requests': len(client.requests)}}
client.artifacts.joinpath('native-single-proof.json').write_text(json.dumps(proof, indent=2))
print(json.dumps(proof))
