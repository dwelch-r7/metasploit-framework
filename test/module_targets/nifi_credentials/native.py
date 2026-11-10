"""Real NiFi configuration producer and independent file/credential controls."""
import base64
import gzip
import hashlib
import json
import os
from pathlib import Path
import re
import sys
import xml.etree.ElementTree as ET

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'nifi_execution'))
from api import NativeClient, NifiTarget, wait_until
from actions import seed, verify_canary

BASE = '/opt/nifi/nifi-current'
FILES = ('nifi.properties', 'flow.json.gz', 'login-identity-providers.xml', 'authorizers.xml')
STORED_DB_PASSWORD = r'module-target-db-"quoted"-password\path'
STORED_ACCOUNT_NAME = 'moduletargetaccount'
STORED_SAS_TOKEN = 'module-target-stored-sas-token'


def bootstrap_control(target, artifacts):
    # This is a genuine vendor id ELF, not a simulated session. Network session
    # qualification happens later with actual Framework-generated payload bytes.
    raw = target.execute('cat', '/usr/bin/id')
    assert raw.startswith(b'\x7fELF')
    source = artifacts / 'shell-session.elf'
    source.write_bytes(raw)
    controls = []
    for user, uid in [('root', 0), ('nifi', 1000), ('labuser', 1001)]:
        log = '/tmp/module-target-nifi-session.log' if user == 'nifi' else '/tmp/module-target-session.log'
        target.execute('rm', '-f', log, '/tmp/shell-session.elf')
        argv = ['runuser', '-u', 'nifi', '--', 'python3', '/opt/launch_nifi_session.py', '/opt/module-target-artifacts/shell-session.elf'] if user == 'nifi' else ['python3', '/opt/launch_session.py', '/opt/module-target-artifacts/shell-session.elf', user]
        launched = json.loads(target.execute(*argv))
        identity = wait_until(lambda: (lambda text: text if text.startswith('uid=' + str(uid) + '(' + user + ')') else None)(target.execute('sh', '-c', 'if test -f ' + log + '; then cat ' + log + '; fi').decode()))
        controls.append({'user': user, 'uid': uid, 'launcher': launched, 'actual_vendor_elf_identity': identity})
        target.execute('rm', '-f', log, '/tmp/shell-session.elf')
    source.unlink()
    return {'kind': 'Native vendor id ELF launcher control, not a network session', 'vendor_id_sha256': hashlib.sha256(raw).hexdigest(), 'identities': controls}


def file_snapshot(target):
    result = {}
    for name in FILES:
        path = BASE + '/conf/' + name
        raw = target.execute('cat', path)
        result[name] = {'sha256': hashlib.sha256(raw).hexdigest(), 'bytes': len(raw), 'stat': target.execute('stat', '-c', '%u:%g:%a', path).decode().strip()}
    return result


def configure_service(target, name, kind, properties):
    created = target.create('controller-services', name, kind)
    status, current, raw = target.request('/nifi-api/controller-services/' + created['id'], method='PUT', data={'revision': created['revision'], 'component': {'id': created['id'], 'properties': properties}})
    assert status == 200, (status, raw)
    assert current['component']['state'] == 'DISABLED', current
    return {'id': created['id'], 'name': name, 'type': kind, 'configured_properties': properties, 'actual_properties': current['component']['properties'], 'descriptors': current['component']['descriptors'], 'external_authentication': 'Not attempted; genuine disabled configuration only'}


def seed_credentials(target):
    canary = seed(target)
    properties = dict(line.split('=', 1) for line in target.execute('cat', BASE + '/conf/nifi.properties').decode().splitlines() if line and not line.startswith('#') and '=' in line)
    stores = {}
    for label in ('keystore', 'truststore'):
        path = properties['nifi.security.' + label]
        if path.startswith('./'):
            path = BASE + '/' + path[2:]
        password = properties['nifi.security.' + label + 'Passwd']
        listing = target.execute('keytool', '-list', '-keystore', path, '-storepass', password, '-storetype', 'PKCS12').decode()
        assert 'Your keystore contains' in listing, listing
        stores[label] = {'path': path, 'password': password, 'native_listing': listing}
    services = []
    services.append(configure_service(target, 'Module target native generic database secret', 'org.apache.nifi.dbcp.DBCPConnectionPool', {'Database Connection URL': 'jdbc:postgresql://unrelated:5432/module_target', 'Database Driver Class Name': 'org.postgresql.Driver', 'Database User': 'module-target-db-user', 'Password': STORED_DB_PASSWORD}))
    services.append(configure_service(target, 'Module target native TLS stores', 'org.apache.nifi.ssl.StandardRestrictedSSLContextService', {'Keystore Filename': stores['keystore']['path'], 'Keystore Password': stores['keystore']['password'], 'Keystore Type': 'PKCS12', 'key-password': properties['nifi.security.keyPasswd'], 'Truststore Filename': stores['truststore']['path'], 'Truststore Password': stores['truststore']['password'], 'Truststore Type': 'PKCS12', 'SSL Protocol': 'TLS'}))
    kinds = {item['type'] for item in target.types('controller-service')}
    azure = next((kind for kind in ('org.apache.nifi.services.azure.storage.AzureStorageCredentialsControllerService_v12', 'org.apache.nifi.services.azure.storage.AzureStorageCredentialsControllerService') if kind in kinds), None)
    assert azure, sorted(kind for kind in kinds if 'AzureStorageCredentials' in kind)
    services.append(configure_service(target, 'Module target native Azure stored configuration', azure, {'storage-account-name': STORED_ACCOUNT_NAME, 'storage-sas-token': STORED_SAS_TOKEN, 'storage-endpoint-suffix': 'core.windows.net'}))
    return {'canary': canary, 'stores': stores, 'services': services}


def read_final_files(target, seed_data, artifacts):
    identifiers = {seed_data['canary']['id']} | {item['id'] for item in seed_data['services']}
    def serialized():
        raw = target.execute('cat', BASE + '/conf/flow.json.gz')
        document = json.loads(gzip.decompress(raw))
        components = {item.get('instanceIdentifier'): item for item in document['rootGroup']['processors'] + document['rootGroup']['controllerServices']}
        if not identifiers <= components.keys():
            return None
        # A creation snapshot can contain all IDs before their final properties.
        # Wait for actual vendor serialization, not just HTTP acceptance.
        canary_password = components[seed_data['canary']['id']]['properties'].get('Password')
        if not isinstance(canary_password, str) or not canary_password.startswith('enc{'):
            return None
        for service in seed_data['services']:
            actual = components[service['id']]['properties']
            for name, value in service['configured_properties'].items():
                if service['descriptors'][name]['sensitive']:
                    if not isinstance(actual.get(name), str) or not actual[name].startswith('enc{'):
                        return None
                elif actual.get(name) != value:
                    return None
        return raw, document
    raw_flow, flow = wait_until(serialized)
    for name in FILES:
        raw = raw_flow if name == 'flow.json.gz' else target.execute('cat', BASE + '/conf/' + name)
        (artifacts / ('native-' + name)).write_bytes(raw)
    output = target.client.command('node', 'test/module_targets/nifi_credentials/decrypt.mjs', str(artifacts / 'native-nifi.properties'), str(artifacts / 'native-flow.json.gz'))
    crypto = json.loads(output)
    private_values = [seed_data['canary']['password'], STORED_DB_PASSWORD, STORED_SAS_TOKEN, seed_data['stores']['keystore']['password'], seed_data['stores']['truststore']['password'], seed_data['services'][1]['configured_properties']['key-password']]
    expected = private_values + [STORED_ACCOUNT_NAME]
    actual = [item['plaintext'] for item in crypto['decrypted']]
    assert all(value in actual for value in expected), (expected, actual)
    (artifacts / 'native-independent-crypto.json').write_text(json.dumps(crypto, indent=2) + '\n')
    identity = ET.fromstring((artifacts / 'native-login-identity-providers.xml').read_bytes())
    accounts = []
    for provider in identity.findall('provider'):
        fields = {item.attrib['name']: item.text for item in provider.findall('property')}
        if fields.get('Username') and fields.get('Password'):
            assert re.fullmatch(r'\$2[aby]\$\d\d\$.{53}', fields['Password']), fields
            accounts.append({'identifier': provider.findtext('identifier'), 'username': fields['Username'], 'hash': fields['Password']})
    assert len(accounts) == 1, accounts
    return {'crypto': crypto, 'identity': accounts, 'flow_root': flow['rootGroup']['name'], 'private_values': private_values}


def derived_files(target):
    # These are explicit parser/file-boundary counterfactuals copied from genuine
    # vendor output. They are not claimed to be running NiFi configurations.
    code = r'''
from pathlib import Path
import gzip, json, os, shutil
source = Path('/opt/nifi/nifi-current/conf')
root = Path('/tmp/module-target-nifi-files')
assert not root.exists()
root.mkdir(mode=0o755)
for mode in ('private', 'missing', 'identity-only', 'missing-key', 'unsupported-algorithm', 'corrupt-tag', 'explicit files'):
    directory = root / mode / 'conf'
    directory.mkdir(parents=True)
    for name in ('nifi.properties', 'flow.json.gz', 'login-identity-providers.xml', 'authorizers.xml'):
        if mode == 'missing' or (mode == 'identity-only' and name != 'login-identity-providers.xml'):
            continue
        shutil.copyfile(source / name, directory / name)
    if mode == 'private':
        (root / mode).chmod(0o700)
    elif mode == 'missing-key':
        path = directory / 'nifi.properties'
        path.write_text(''.join(line for line in path.read_text().splitlines(True) if not line.startswith('nifi.sensitive.props.key=')))
    elif mode == 'unsupported-algorithm':
        path = directory / 'nifi.properties'
        path.write_text(path.read_text().replace('nifi.sensitive.props.algorithm=NIFI_PBKDF2_AES_GCM_256', 'nifi.sensitive.props.algorithm=MODULE_TARGET_UNSUPPORTED'))
    elif mode == 'corrupt-tag':
        path = directory / 'flow.json.gz'
        document = json.loads(gzip.decompress(path.read_bytes()))
        processor = next(item for item in document['rootGroup']['processors'] if item['type'] == 'org.apache.nifi.processors.standard.GetHTTP')
        encrypted = processor['properties']['Password']
        processor['properties']['Password'] = encrypted[:-2] + ('0' if encrypted[-2] != '0' else '1') + '}'
        path.write_bytes(gzip.compress(json.dumps(document).encode()))
print(json.dumps({'root': str(root), 'modes': sorted(path.name for path in root.iterdir()), 'producer_uid': os.getuid()}))
'''
    output = target.client.command(*target.client.runtime['compose'], 'exec', '-T', '--user', '1000:1000', 'linux', 'python3', '-c', code)
    result = json.loads(output)
    assert result['producer_uid'] == 1000, result
    denied = target.execute('runuser', '-u', 'labuser', '--', 'sh', '-c', 'if test -r /tmp/module-target-nifi-files/private/conf/nifi.properties; then printf readable; else printf denied; fi').decode()
    assert denied == 'denied', denied
    result['labuser_private_read'] = denied
    return result


def main():
    action, tag = sys.argv[1:3]
    assert re.fullmatch(r'[a-zA-Z0-9_-]+', tag), tag
    runtime = json.loads(Path(os.environ['MODULE_TARGET_RUNTIME']).read_text())
    artifacts = Path(runtime['artifacts'])
    client = NativeClient(runtime, 'native-credentials-' + tag + '.json')
    facts_path = artifacts / 'nifi-credentials-facts.json'
    try:
        if action == 'preflight':
            target = NifiTarget(client, 'linux', profile_name='vulnerable')
            facts = target.verify()
            facts['service_identity'] = client.command(*runtime['compose'], 'exec', '-T', '--user', '1000:1000', 'linux', 'id').decode().strip()
            assert facts['service_identity'].startswith('uid=1000(nifi) gid=1000(nifi)'), facts
            processes = target.execute('ps', '-eo', 'uid,pid,args').decode()
            assert any(line.split()[0] == '1000' and 'org.apache.nifi.NiFi' in line for line in processes.splitlines()), processes
            facts['actual_processes'] = processes
            database = ['psql', '-h', '127.0.0.1', '-U', 'module_framework', '-d', 'module_targets', '-v', 'ON_ERROR_STOP=1', '-Atc', 'SELECT current_database()']
            valid_db = client.execute('reporting_db', 'env', 'PGPASSWORD=module-target-framework-db-password', *database).decode().strip()
            assert valid_db == 'module_targets', valid_db
            refused_db = client.execute('reporting_db', 'sh', '-c', 'if PGPASSWORD=module-target-wrong-db-password psql -h 127.0.0.1 -U module_framework -d module_targets -Atc "SELECT current_database()" >/dev/null 2>&1; then exit 1; else printf rejected; fi').decode()
            assert refused_db == 'rejected', refused_db
            facts['independent_reporting_database_auth'] = {'database': valid_db, 'wrong_password': refused_db}
            expected = json.loads(Path('test/module_targets/nifi_credentials/vendor-source-sha256.json').read_text())
            checksums = target.execute('sha256sum', *expected['files']).decode()
            actual = {line.split(None, 1)[1]: line.split()[0] for line in checksums.splitlines()}
            assert actual == expected['files'], actual
            facts['vendor_source_conservation'] = {'pinned_stock_image': expected['image'], 'actual_files': actual}
            facts['bootstrap_control'] = bootstrap_control(target, artifacts)
            facts['seed'] = seed_credentials(target)
            facts['native_files'] = read_final_files(target, facts['seed'], artifacts)
            facts['derived_files'] = derived_files(target)
            def settled_graph():
                graph = target.graph()
                return graph if all(item.get('validationStatus') in ('VALID', 'INVALID') for item in graph['processors'] + graph['services']) else None
            facts['initial_graph'] = wait_until(settled_graph)
            facts['initial_files'] = file_snapshot(target)
            facts_path.write_text(json.dumps(facts, indent=2) + '\n')
            return facts
        facts = json.loads(facts_path.read_text())
        target = NifiTarget(client, 'linux', profile_name='vulnerable', token=facts['token'])
        if action == 'snapshot':
            return {'files': file_snapshot(target), 'graph': target.graph()}
        if action == 'verify-canary':
            return verify_canary(target, {'canary': facts['seed']['canary']}, client)
        raise ValueError('Unknown post native operation ' + action)
    finally:
        client.save()


if __name__ == '__main__':
    print(json.dumps(main()))
