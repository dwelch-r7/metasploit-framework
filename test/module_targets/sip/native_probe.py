"""Prove the real server policies, clients, authentication and owned state first."""
import base64
import json
import os
from pathlib import Path
import re
import time
from native_client import NativeSIP
from client_api import ami as native_ami, sip as native_sip

runtime = json.loads(Path(os.environ['MODULE_TARGET_RUNTIME']).read_text())
client = NativeSIP(runtime)
started = time.monotonic()
profiles = {}
profile = os.environ.get('SIP_TARGET_PROFILE', 'full')
assert profile in ['full', 'options', 'enumeration', 'capture', 'ami']
try:
    for service in ['exposed', 'protected']:
        identifier = client.process(runtime['compose'] + ['ps', '-q', service]).decode().strip()
        detail = json.loads(client.process(['docker', 'inspect', identifier]))[0]
        assert not detail['HostConfig']['Privileged'] and detail['HostConfig']['Init']
        assert not detail['Mounts']
        assert {cap.removeprefix('CAP_') for cap in detail['HostConfig']['CapDrop']} >= {'SYS_ADMIN', 'SYS_TIME'}
        status = client.command(service, 'cat', '/proc/1/status').decode()
        capabilities = int(next(line.split()[1] for line in status.splitlines() if line.startswith('CapEff:')), 16)
        assert capabilities & ((1 << 21) | (1 << 25)) == 0
        version = client.command(service, 'asterisk', '-rx', 'core show version').decode()
        assert version.startswith('Asterisk 18.10.0~dfsg+~cs6.10.40431411-2 ')
        settings = client.command(service, 'asterisk', '-rx', 'sip show settings').decode()
        assert 'UDP Bindaddress:        0.0.0.0:5060' in settings and 'TCP SIP Bindaddress:    0.0.0.0:5060' in settings
        assert 'TLS SIP Bindaddress:    0.0.0.0:5061' in settings
        assert 'Always auth rejects:    ' + ('Yes' if service == 'protected' else 'No') in settings
        users = client.command(service, 'asterisk', '-rx', 'sip show users').decode()
        assert re.findall(r'^(\d+)\s', users, re.M) == ['1000', '1001']
        hashes = client.command(service, 'sha256sum', '/etc/asterisk/sip.conf', '/etc/asterisk/manager.conf', '/etc/asterisk/modules.conf', '/etc/asterisk/extensions.conf').decode()
        profiles[service] = dict(version=version, settings=settings, users=users, configuration_hashes=hashes, inactive=client.inactive(service))
    versions = client.command('client', 'dpkg-query', '-W', '-f', '${Package} ${Version}\n', 'asterisk', 'sipsak', 'sip-tester').decode()
    assert 'sipsak 0.9.8.1-1build1' in versions and 'sip-tester 1:3.6.1-1build1' in versions
    published, loopback = {}, []
    for service, port, protocols in [('exposed', 5060, ['udp', 'tcp']), ('protected', 5060, ['udp', 'tcp']), ('unrelated', 53, ['udp', 'tcp']), ('exposed', 5038, ['tcp']), ('exposed', 5061, ['tcp'])]:
        for protocol in protocols:
            binding = client.process(runtime['compose'] + ['port', '--protocol', protocol, service, str(port)]).decode().strip()
            assert re.fullmatch(r'127\.0\.0\.1:[1-9]\d*', binding), binding
            published[f'{service}/{port}/{protocol}'] = int(binding.rsplit(':', 1)[1])
            if port == 5060:
                request = dict(host='127.0.0.1', port=published[f'{service}/{port}/{protocol}'], transport=protocol, method='OPTIONS', account='1000')
                response = native_sip(request)
                assert response['responses'][0]['code'] == (200 if service == 'exposed' else 401), response
                loopback.append(dict(operation=request, result=response))
    manager_loopback = []
    for username, password, accepted in [('module_manager', 'module-target-manager-password', True), ('module_manager', 'module-target-wrong-password', False), ('missing_manager', 'module-target-manager-password', False)]:
        request = dict(host='127.0.0.1', port=published['exposed/5038/tcp'], username=username, password=password)
        response = native_ami(request)
        assert response['reply'].startswith('Response: Success\r\n' if accepted else 'Response: Error\r\n'), response
        manager_loopback.append(dict(operation=request, result=response))
    operations = [dict(host=client.ip(role), role=role, transport=transport, method=method, account=account, expires=0) for role in ['exposed', 'protected'] for transport in ['udp', 'tcp', 'tls'] for method in ['OPTIONS', 'REGISTER'] for account in ['1000', '1001', '1002']]
    matrix = client.api(operations)
    assert len(matrix) == 36
    for row in matrix:
        operation, result = row['operation'], row['result']
        assert 'error' not in result, row
        code = result['responses'][0]['code']
        expected = (401 if operation['role'] == 'protected' else 404 if operation['account'] == '1002' else 200) if operation['method'] == 'OPTIONS' else (200 if operation['account'] == '1000' else 401 if operation['account'] == '1001' or operation['role'] == 'protected' else 404)
        assert code == expected, row
        if operation['transport'] == 'tls':
            assert result['tls_version'] in ['TLSv1.2', 'TLSv1.3']
    transports = ['udp', 'tcp'] if profile in ['full', 'options', 'enumeration'] else ['udp'] if profile == 'capture' else []
    for transport in transports:
        if profile in ['full', 'options', 'enumeration']:
            for account, expected in [('1000', 200), ('1002', 404)]:
                result = client.sipsak('exposed', transport, account, expected=0 if expected == 200 else 1)
                assert result['codes'] and result['codes'][0] == expected
        if profile in ['full', 'enumeration', 'capture']:
            for expires in [60, 0]:
                result = client.sipsak('exposed', transport, '1001', password='module-target-sip-password', expires=expires, expected=0)
                assert result['codes'] == [401, 200]
                state = client.state('exposed')
                assert (state['peers']['1001']['address'] not in ['(null)', '(Unspecified)']) == bool(expires)
            client.inactive('exposed')
        if profile in ['full', 'capture']:
            for expires in [60, 0]:
                result = client.sipp(client.ip('exposed'), expires=expires, transport=transport)
                state = client.state('exposed')
                assert (state['peers']['1001']['address'] not in ['(null)', '(Unspecified)']) == bool(expires)
            client.inactive('exposed')
    auth, wildcard, ami = [], [], []
    if profile in ['full', 'enumeration']:
        for password, response in [('module-target-sip-password', 200), ('module-target-wrong-password', 403)]:
            client.sipp(client.ip('protected'), method='OPTIONS', password=password, response=response)
            client.inactive('protected')
    if profile in ['full', 'enumeration']:
        for transport in ['udp', 'tcp', 'tls']:
            for password, expected in [('module-target-sip-password', 200), ('module-target-wrong-password', 403), ('module-target-s', 403)]:
                row = client.api([dict(host=client.ip('exposed'), transport=transport, method='REGISTER', account='1001', expires=0, password=password)])[0]
                assert 'error' not in row['result'] and [response['code'] for response in row['result']['responses']] == [401, expected], row
                auth.append(row)
            client.inactive('exposed')
    if profile in ['full', 'enumeration']:
        for account, password, expected in [('1000', None, 200), ('1001', 'module-target-sip-password', 401)]:
            seeded = client.api([dict(host=client.ip('exposed'), transport='udp', method='REGISTER', account=account, expires=60, password=password)])[0]
            assert seeded['result']['responses'][-1]['code'] == 200, seeded
            assert client.state('exposed')['peers'][account]['address'] not in ['(null)', '(Unspecified)']
            removed = client.api([dict(host=client.ip('exposed'), transport='udp', method='REGISTER', account=account, expires=0, wildcard=True, from_account=True)])[0]
            assert removed['result']['responses'][-1]['code'] == expected, removed
            assert (client.state('exposed')['peers'][account]['address'] in ['(null)', '(Unspecified)']) == (expected == 200)
            client.unregister('exposed', account)
            wildcard.append(dict(seeded=seeded, wildcard=removed))
    legacy = []
    if profile == 'enumeration':
        settings = client.command('permissive', 'asterisk', '-rx', 'sip show settings').decode()
        assert re.search(r'Pedantic SIP support:\s+(No)', settings), settings
        configuration = client.command('permissive', 'cat', '/etc/asterisk/sip.conf').decode()
        assert configuration.endswith('[general](+)\npedantic=no\n')
        ordinary = client.command('exposed', 'cat', '/etc/asterisk/sip.conf').decode()
        assert configuration == ordinary + '\n[general](+)\npedantic=no\n'
        profiles['permissive'] = dict(settings=settings, configuration=configuration)
        for account, password, expected in [('1000', None, 200), ('1001', 'module-target-sip-password', 401)]:
            client.inactive('permissive')
            seeded = client.sipsak('permissive', 'udp', account, password=password, expires=60)
            before = client.state('permissive')
            try:
                response = client.legacy_register('permissive', account)
                after = client.state('permissive')
                row = dict(account=account, seeded=seeded, before=before, response=response, after=after)
                legacy.append(row)
                assert response['sender_local'][1] == 5060
                assert {item['code'] for item in response['responses']} == {expected}, row
                assert {item['socket'] for item in response['responses']} == {'sender'}, row
                assert (after['registry'] == {} if expected == 200 else after['registry'] == before['registry']), row
            finally:
                client.unregister('permissive', account)
        assert client.command('permissive', 'cat', '/etc/asterisk/sip.conf').decode() == configuration
        profiles['permissive']['final_inactive'] = client.inactive('permissive')
    rejected = client.api([dict(host=client.ip('exposed'), transport='tls', method='OPTIONS', account='1000', trust='system')])[0]
    assert rejected['result'].get('error_type') == 'SSLCertVerificationError', rejected
    if profile in ['full', 'ami']:
        ami = client.api([dict(api='ami', host=client.ip('exposed'), username=username, password=password, commands=['sip show users', 'core show version']) for username, password in [('module_manager', 'module-target-manager-password'), ('module_manager', 'module-target-wrong-password'), ('missing_manager', 'module-target-manager-password')]])
        for index, row in enumerate(ami):
            assert 'error' not in row['result'], row
            assert base64.b64decode(row['result']['banner_base64']).startswith(b'Asterisk Call Manager/')
            assert row['result']['reply'].startswith('Response: Success\r\n' if index == 0 else 'Response: Error\r\n'), row
        assert 'module-target-s' in ami[0]['result']['commands'][0]['reply'] and 'module-target-sip-password' not in ami[0]['result']['commands'][0]['reply']
    dns = client.command('unrelated', 'dig', '+time=1', '+tries=1', '+short', '@127.0.0.1', 'module-target.test', 'A').decode().strip()
    assert dns == '192.0.2.10'
    database = client.command('reporting_db', 'env', 'PGPASSWORD=module-target-framework-db-password', 'psql', '-h', '127.0.0.1', '-U', 'module_framework', '-d', 'module_targets', '-Atc', 'SELECT current_user,current_database(),version()').decode()
    assert database.startswith('module_framework|module_targets|PostgreSQL 16.')
    for service in ['exposed', 'protected']:
        profiles[service]['final_inactive'] = client.inactive(service)
        assert client.command(service, 'sha256sum', '/etc/asterisk/sip.conf', '/etc/asterisk/manager.conf', '/etc/asterisk/modules.conf', '/etc/asterisk/extensions.conf').decode() == profiles[service]['configuration_hashes']
    report = dict(client_address=client.ip('client'), profiles=profiles, matrix=matrix, authentication=auth, wildcard=wildcard, legacy=legacy, tls_rejected=rejected, ami=ami, versions=versions, database=database, published=published, loopback=loopback, manager_loopback=manager_loopback)
finally:
    (Path(runtime['artifacts'])/'native-probe-partial.json').write_text(json.dumps(dict(commands=client.commands, profiles=profiles, seconds=time.monotonic()-started), indent=2))
print(json.dumps(dict(report, profile=profile, commands=client.commands, seconds=time.monotonic()-started), indent=2))
