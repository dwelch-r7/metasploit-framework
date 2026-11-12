"""Independently verify three Salt hosts, native delivery, and reporting auth."""
import base64
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import uuid

runtime = json.loads(Path(sys.argv[1]).read_text())
phase = sys.argv[2]
source = Path(__file__).parent
pins = json.loads((source.parent / 'saltstack_zeromq/profiles.json').read_text())
rce = json.loads((source.parent / 'saltstack_rce/vendor-files.json').read_text())
gather = json.loads((source.parent / 'saltstack_gather/vendor-files.json').read_text())
configuration = {'vendor_files': dict(pins['packages']['3000.1']['vendor_files'],
                                      **rce['extra_vendor_files'], **gather['vendor_files']),
                 'packages': {row['package']: row['version'] for row in pins['runtime']}}
services = {'master': 'master', 'minion_a': 'minion-a', 'minion_b': 'minion-b'}
record = {'status': 'starting', 'phase': phase, 'commands': []}
cleanup = {service: [] for service in services}


def execute(service, *argv, expected=0, stdin=None, timeout=240):
    result = subprocess.run(runtime['compose'] + ['exec', '-T', service, *argv],
                            input=stdin, capture_output=True, timeout=timeout)
    record['commands'].append({'service': service, 'argv': argv, 'exitstatus': result.returncode,
                               'stdout_base64': base64.b64encode(result.stdout).decode(),
                               'stderr_base64': base64.b64encode(result.stderr).decode()})
    assert result.returncode == expected, record['commands'][-1]
    return result.stdout.decode()


def document(raw, prefix):
    rows = [line[len(prefix):] for line in raw.splitlines() if line.startswith(prefix)]
    assert len(rows) == 1
    return json.loads(rows[0])


def identity(service):
    return document(execute(service, 'python', '-c', (source / 'identity.py').read_text(),
                            stdin=json.dumps(configuration).encode()), 'SALT_DEPLOY_IDENTITY=')


try:
    record['identities'] = {role: identity(service) for service, role in services.items()}
    assert len({row['mount_namespace'] for row in record['identities'].values()}) == 3
    record['addresses'] = {}
    for service, role in services.items():
        address = execute(service, 'python', '-c', 'import socket;print(socket.gethostbyname(socket.gethostname()))').strip()
        record['addresses'][role] = {'service': service, 'address': address}
    assert len({value['address'] for value in record['addresses'].values()}) == 3
    isolation = '/tmp/module-target-deployer-isolation-' + uuid.uuid4().hex
    for service, role in services.items():
        cleanup[service].append(isolation)
        execute(service, 'python', '-c', 'from pathlib import Path;import sys;Path(sys.argv[1]).write_text(sys.argv[2])', isolation, role)
    for service, role in services.items():
        assert execute(service, 'cat', isolation) == role
    if phase == 'before':
        script = b'#!/bin/sh\nprintf "SALT_DEPLOY_ROLE=%s\\nSALT_DEPLOY_TOKEN=%s\\nSALT_DEPLOY_UID=" "$MSF_MODULE_TARGET_ROLE" "$MSF_MODULE_TARGET_TOKEN"\nid -u\n'
        encoded = base64.b64encode(script)
        cases = []
        for name, selector in [('all', '*'), ('selected', 'module-target-minion-a')]:
            identifier = uuid.uuid4().hex
            upload = '/tmp/module-target-deployer-source-' + identifier
            executable = '/tmp/module-target-deployer-exe-' + identifier
            cases.append({'name': name, 'selector': selector, 'source': upload,
                          'encoded_destination': executable + '.b64', 'executable_destination': executable,
                          'bytes_base64': base64.b64encode(encoded).decode()})
            cleanup['master'].append(upload)
            for service in ['minion_a', 'minion_b']:
                cleanup[service] += [executable, executable + '.b64']
        controls = {'cases': cases, 'tokens': {role: value['state']['token'] for role, value in record['identities'].items()}}
        record['deployment'] = document(execute('master', 'python', '-c', (source / 'control.py').read_text(),
            stdin=json.dumps(controls).encode(), timeout=420), 'SALT_DEPLOY_NATIVE=')
        assert record['deployment']['status'] == 'native_deployment_passed'
        for case in cases:
            assert execute('master', 'sha256sum', case['source']).split()[0] == hashlib.sha256(encoded).hexdigest()
            for service, role in services.items():
                code = 'import hashlib,json,pathlib,sys;print(json.dumps({name:{"sha256":hashlib.sha256(pathlib.Path(name).read_bytes()).hexdigest(),"mode":oct(pathlib.Path(name).stat().st_mode&511)} if pathlib.Path(name).exists() else None for name in sys.argv[1:]}))'
                files = json.loads(execute(service, 'python', '-c', code, case['encoded_destination'], case['executable_destination']))
                selected = service != 'master' and (case['selector'] == '*' or role == 'minion-a')
                if selected:
                    assert files[case['encoded_destination']]['sha256'] == hashlib.sha256(encoded).hexdigest()
                    assert files[case['executable_destination']]['sha256'] == hashlib.sha256(script).hexdigest()
                    assert files[case['executable_destination']]['mode'] == '0o755'
                else:
                    assert all(value is None for value in files.values())
    else:
        code = "import json,salt.client;print(json.dumps(salt.client.get_local_client('/etc/salt/master').cmd('module-target-minion-*','test.ping',timeout=15)))"
        record['post_deployment_ping'] = json.loads(execute('master', 'python', '-c', code))
        assert record['post_deployment_ping'] == {'module-target-minion-a': True, 'module-target-minion-b': True}
    pg = ['psql', '-h', '127.0.0.1', '-U', 'module_framework', '-d', 'module_targets', '-v', 'ON_ERROR_STOP=1', '-Atc']
    record['postgres_version'] = execute('reporting_db', 'env', 'PGPASSWORD=module-target-framework-db-password', *pg, 'SELECT version()').strip()
    assert not execute('reporting_db', 'env', 'PGPASSWORD=module-target-rejected-password', *pg, 'SELECT 1', expected=2)
    record['status'] = 'native_passed'
except Exception as error:
    record.update(status='native_failed', error=repr(error))
    raise
finally:
    primary_error = sys.exc_info()[1]
    cleanup_errors = []
    for service, paths in cleanup.items():
        code = 'import json,pathlib,sys;paths=[pathlib.Path(name) for name in sys.argv[1:]];[p.unlink() for p in paths if p.exists()];print(json.dumps([str(p) for p in paths if p.exists()]))'
        try:
            assert json.loads(execute(service, 'python', '-c', code, *paths)) == []
        except Exception as error:
            cleanup_errors.append({'service': service, 'error': repr(error)})
    if 'identities' in record:
        try:
            record['identities_after'] = {role: identity(service) for service, role in services.items()}
            assert record['identities_after'] == record['identities']
        except Exception as error:
            cleanup_errors.append({'identity': repr(error)})
    record['cleanup_errors'] = cleanup_errors
    if cleanup_errors:
        record['status'] = 'native_failed'
    destination = Path(runtime['artifacts']) / ('native-' + phase + '.json')
    destination.write_text(json.dumps(record, indent=2) + '\n')
    print(json.dumps({'status': record['status'], 'evidence': str(destination)}))
    if cleanup_errors and primary_error is None:
        raise RuntimeError('Native cleanup or identity proof failed: ' + repr(cleanup_errors))
