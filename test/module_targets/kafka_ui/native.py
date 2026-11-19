"""Native Kafka/UI checks using unmodified stock images and existing tools."""
from pathlib import Path
import base64
import hashlib
import json
import os
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

runtime = json.loads(Path(sys.argv[1]).read_text())
version, operation = sys.argv[2:4]
artifacts = Path(runtime['artifacts'])
state_path = artifacts / 'kafka-ui-native-state.json'
endpoint = runtime['endpoints']['app']
origin = 'http://' + endpoint['host'] + ':' + str(endpoint['port'])
cluster = 'module-native'
expected_groovy = os.environ.get('KAFKA_UI_EXPECT_GROOVY', 'true') == 'true'
record = {'version': version, 'operation': operation, 'expected_groovy': expected_groovy, 'checks': [], 'commands': [], 'http': []}


def check(name, passed):
    record['checks'].append({'name': name, 'passed': bool(passed)})
    if not passed:
        raise AssertionError(name)


def command(role, *arguments, data=None, timeout=25, required=True):
    argv = runtime['compose'] + ['exec', '-T', role, *arguments]
    result = subprocess.run(argv, input=data, capture_output=True, timeout=timeout)
    record['commands'].append({'argv': argv, 'exit': result.returncode, 'stdout_base64': base64.b64encode(result.stdout).decode(), 'stderr': result.stderr.decode(errors='replace')})
    if required and result.returncode:
        raise RuntimeError('Native command failed: ' + repr(arguments) + ': ' + result.stderr.decode(errors='replace'))
    return result.stdout


def kafka(program, *arguments, data=None):
    return command('broker', 'env', 'KAFKA_HEAP_OPTS=-Xms32m -Xmx64m', '/opt/kafka/bin/kafka-' + program + '.sh', '--bootstrap-server', 'broker:9092', *arguments, data=data)


def request(label, path, params=None, method='GET', document=None):
    url = origin + path
    if params is not None:
        url += '?' + urllib.parse.urlencode(params)
    headers = {'Accept': '*/*'}
    data = None
    if document is not None:
        data = json.dumps(document).encode()
        headers['Content-Type'] = 'application/json'
    try:
        response = urllib.request.urlopen(urllib.request.Request(url, headers=headers, data=data, method=method), timeout=15)
    except urllib.error.HTTPError as error:
        response = error
    body = response.read()
    digest = hashlib.sha256(body).hexdigest()
    filename = 'native-' + label + '-' + digest + '.bytes'
    (artifacts / filename).write_bytes(body)
    record['http'].append({'label': label, 'method': method, 'request_body_base64': base64.b64encode(data).decode() if data is not None else None, 'url': url, 'status': response.code, 'headers': dict(response.headers), 'body_file': filename, 'body_sha256': digest})
    return response.code, body


def topics():
    return sorted(line for line in kafka('topics', '--list').decode().splitlines() if line and not line.startswith('__'))


def consume(topic, count=2):
    data = kafka('console-consumer', '--topic', topic, '--partition', '0', '--from-beginning', '--max-messages', str(count), '--timeout-ms', '12000', '--consumer-property', 'enable.auto.commit=false', '--property', 'print.key=true', '--property', 'key.separator=|')
    return data.decode().splitlines()


def file_state(path):
    output = command('app', 'sh', '-c', 'if [ -f "$1" ]; then stat -c "%u %s" "$1"; base64 "$1"; else printf "ABSENT\\n"; fi', 'native-file', path)
    lines = output.decode().splitlines()
    if lines == ['ABSENT']:
        return {'exists': False}
    uid, size = map(int, lines[0].split())
    contents = base64.b64decode(''.join(lines[1:]))
    check('file-size-matches-bytes', len(contents) == size)
    return {'exists': True, 'uid': uid, 'base64': base64.b64encode(contents).decode()}


def messages(topic, query='', kind='STRING_CONTAINS', limit=2):
    params = {'q': query, 'filterQueryType': kind, 'attempt': 2, 'limit': limit, 'page': 0, 'seekDirection': 'FORWARD', 'keySerde': 'String', 'valueSerde': 'String', 'seekType': 'BEGINNING'}
    return request('messages-' + kind.lower(), '/api/clusters/' + cluster + '/topics/' + urllib.parse.quote(topic, safe='') + '/messages', params)


def resources(phase):
    values = []
    for role in ['app', 'broker']:
        for name in ['memory.events', 'pids.events']:
            output = command(role, 'cat', '/sys/fs/cgroup/' + name).decode()
            fields = dict(line.split() for line in output.splitlines())
            check(phase + '-' + role + '-' + name, all(int(fields.get(key, '0')) == 0 for key in ['oom', 'oom_kill', 'max']))
            values.append({'role': role, 'name': name, 'values': fields})
    record['resources'] = values


def application():
    uid = int(command('app', 'id', '-u').decode().strip())
    check('nonroot-application-user', uid == 100)
    jar = command('app', 'sha256sum', '/kafka-ui-api.jar').decode().split()[0]
    inventory = command('app', 'sh', '-c', 'for tool in sh bash nc curl wget base64 unzip python3; do printf "%s=" "$tool"; command -v "$tool" || true; done').decode()
    record['stock_command_inventory'] = inventory
    record['java_version'] = command('app', 'sh', '-c', 'java -version 2>&1').decode()
    status, body = request('actuator-info', '/actuator/info')
    check('actuator-info-http', status == 200)
    info = json.loads(body)
    record['actuator_info'] = info
    build = info.get('build', {}).get('version', '').lstrip('v')
    if build:
        check('genuine-application-version', build == version)
    else:
        commit = info['git']['commit']['id']
        expected = json.loads(Path('test/module_targets/kafka_ui/releases.json').read_text())['releases'][version]['reference']
        check('genuine-git-identity', expected.startswith(commit))
    status, body = request('clusters', '/api/clusters')
    check('cluster-api-http', status == 200)
    clusters = json.loads(body)
    check('native-cluster-online', any(row['name'] == cluster and row['status'].lower() == 'online' for row in clusters))
    record['clusters'] = clusters
    return {'uid': uid, 'jar_sha256': jar}


def initialize():
    resources('before')
    app = application()
    before = topics()
    check('fresh-native-user-topic-inventory', before == [])
    topic = 'module-target-native-' + str(os.getpid())
    kafka('topics', '--create', '--topic', topic, '--partitions', '1', '--replication-factor', '1')
    expected = ['blue|module-target-native-blue', 'red|module-target-native-red']
    kafka('console-producer', '--topic', topic, '--property', 'parse.key=true', '--property', 'key.separator=|', data=('\n'.join(expected) + '\n').encode())
    offsets = kafka('get-offsets', '--topic', topic).decode().strip()
    record['native_end_offsets'] = offsets
    check('producer-records-acknowledged-by-broker', offsets == topic + ':0:2')
    check('real-broker-produce-consume-bytes', consume(topic) == expected)
    status, body = messages(topic)
    check('native-ui-unfiltered-http', status == 200)
    check('native-ui-both-records', all(value.split('|', 1)[1].encode() in body for value in expected))
    status, body = messages(topic, 'module-target-native-blue', limit=1)
    check('native-literal-filter-http', status == 200)
    check('native-literal-filter-content', b'module-target-native-blue' in body and b'module-target-native-red' not in body)
    state = {'topic': topic, 'topics': topics(), 'messages': expected, 'app': app}
    state_path.write_text(json.dumps(state, indent=2) + '\n')
    return state


def proof():
    state = json.loads(state_path.read_text())
    path = '/tmp/module-target-kafka-native-' + str(os.getpid())
    before = file_state(path)
    check('fresh-native-proof-path', before == {'exists': False})
    contents = 'module-target-native-groovy-proof'
    script = 'new ProcessBuilder("sh","-c",' + json.dumps('printf %s ' + contents + ' > ' + path) + ').start().waitFor(); true'
    try:
        status, body = messages(state['topic'], script, 'GROOVY_SCRIPT', 1)
        record['groovy_http_status'] = status
        value = file_state(path)
        record['native_groovy_proof'] = value
        if expected_groovy:
            check('genuine-groovy-process-execution', value == {'exists': True, 'uid': state['app']['uid'], 'base64': base64.b64encode(contents.encode()).decode()})
        else:
            rejection = json.loads(body)
            record['groovy_rejection'] = {'code': rejection.get('code'), 'message': rejection.get('message')}
            check('groovy-disabled-setting-rejects-request', status == 400 and rejection.get('code') == 4002 and 'filtering.groovy.enabled' in rejection.get('message', ''))
            check('groovy-disabled-proof-absent', value == {'exists': False})
    finally:
        if not before['exists']:
            command('app', 'rm', '-f', path)
            check('native-proof-removed', file_state(path) == {'exists': False})
    resources('after-proof')
    return {'groovy_execution': expected_groovy}


def admin():
    state = json.loads(state_path.read_text())
    check('native-admin-baseline-topics', topics() == state['topics'])
    cycles = []
    for suffix in ['first', 'repeat']:
        topic = 'module-target-admin-' + str(os.getpid()) + '-' + suffix
        path = '/api/clusters/' + cluster + '/topics/' + topic
        created = False
        cycle = {'topic': topic}
        try:
            status, body = request('admin-create-' + suffix, '/api/clusters/' + cluster + '/topics', method='POST', document={'name': topic, 'partitions': 1, 'replicationFactor': 1, 'configs': {'cleanup.policy': 'delete', 'retention.bytes': '-1'}})
            created = status == 200
            check('native-admin-create-http-' + suffix, created)
            check('native-admin-create-identity-' + suffix, json.loads(body).get('name') == topic)
            check('native-admin-topic-exists-' + suffix, topics() == sorted(state['topics'] + [topic]))
            contents = 'module-target-native-admin-' + suffix
            status, body = request('admin-produce-' + suffix, path + '/messages', method='POST', document={'partition': 0, 'key': 'admin', 'content': contents, 'keySerde': 'String', 'valueSerde': 'String'})
            check('native-admin-produce-http-' + suffix, status == 200)
            check('native-admin-real-broker-bytes-' + suffix, consume(topic, 1) == ['admin|' + contents])
            status, body = messages(topic, limit=1)
            check('native-admin-ui-read-' + suffix, status == 200 and contents.encode() in body)
            cycle['message'] = contents
        finally:
            if created:
                status, body = request('admin-delete-' + suffix, path, method='DELETE')
                check('native-admin-delete-http-' + suffix, status == 200)
                check('native-admin-exact-baseline-restored-' + suffix, topics() == state['topics'])
        cycles.append(cycle)
    record['admin_cycles'] = cycles
    check('native-admin-sentinel-records-preserved', consume(state['topic']) == state['messages'])
    resources('after-admin')
    return {'cycles': cycles}


def command_proof():
    command_text, path, expected_base64 = sys.argv[4:7]
    check('native-command-controlled-path', path.startswith('/tmp/module-target-kafka-command-') and '/' not in path[len('/tmp/'):])
    state = json.loads(state_path.read_text())
    check('native-command-fresh-path', file_state(path) == {'exists': False})
    record['command_proof'] = {'command_base64': base64.b64encode(command_text.encode()).decode(), 'path': path, 'expected_base64': expected_base64}
    record['artifact_name'] = 'kafka-ui-native-command-' + hashlib.sha256(command_text.encode()).hexdigest() + '.json'
    encoded = base64.b64encode(command_text.encode()).decode()
    record['command_proof']['transport'] = 'jdk-base64-utf8-native-control-only'
    script = 'new ProcessBuilder("sh","-c",new String(java.util.Base64.getDecoder().decode("' + encoded + '"),"UTF-8")).start().waitFor(); true'
    try:
        status, body = messages(state['topic'], script, 'GROOVY_SCRIPT', 1)
        value = file_state(path)
        record['command_proof']['actual'] = value
        if expected_groovy:
            check('native-exact-command-http', status == 200)
            check('native-exact-command-content-and-user', value == {'exists': True, 'uid': 100, 'base64': expected_base64})
        else:
            rejection = json.loads(body)
            check('native-exact-command-setting-denial', status == 400 and rejection.get('code') == 4002 and 'filtering.groovy.enabled' in rejection.get('message', ''))
            check('native-disabled-command-proof-absent', value == {'exists': False})
    finally:
        command('app', 'rm', '-f', path)
        check('native-command-proof-removed', file_state(path) == {'exists': False})
    resources('after-command-proof')
    return record['command_proof']


def audit():
    state = json.loads(state_path.read_text())
    app = application()
    check('application-jar-and-user-preserved', app == state['app'])
    check('native-user-topics-preserved', topics() == state['topics'])
    check('native-broker-messages-preserved', consume(state['topic']) == state['messages'])
    status, body = messages(state['topic'])
    check('native-ui-reads-preserved', status == 200 and all(value.split('|', 1)[1].encode() in body for value in state['messages']))
    resources('after')
    return state


if __name__ == '__main__':
    try:
        result = {'initialize': initialize, 'admin': admin, 'proof': proof, 'command_proof': command_proof, 'audit': audit}[operation]()
        record.update(passed=True, data=result)
    except Exception as error:
        record.update(passed=False, error={'type': type(error).__name__, 'message': str(error)})
    finally:
        (artifacts / record.get('artifact_name', 'kafka-ui-native-' + operation + '.json')).write_text(json.dumps(record, indent=2) + '\n')
        print(json.dumps(record))
    if not record.get('passed'):
        raise SystemExit(1)
