"""Native execution prerequisite and explicit recovery for the isolated full stack."""
import json
import os
from pathlib import Path
import re
import sys

from client import ExecutionClient, KEYS

runtime = json.loads(Path(os.environ['MODULE_TARGET_RUNTIME']).read_text())
artifacts = Path(runtime['artifacts'])
mode, phase = sys.argv[1:3]
assert mode in ['control', 'snapshot', 'restore', 'settle'] and re.fullmatch(r'[a-z0-9_-]+', phase)
client = ExecutionClient(runtime)
proof = {}
try:
    state = client.state()
    if mode == 'snapshot':
        proof = state
    elif mode in ['restore', 'settle']:
        baseline = json.loads((artifacts / 'native-baseline.json').read_text())
        client.full_configuration = baseline['all_configuration']
        if mode == 'restore':
            response, _ = client.request('/index.php', {'loginpassword': 'module-target-netalertx-password'}, True)
            assert response['status'] == 302
            assert client.settings({}, True)['status'] == 200
        proof = client.wait(lambda s: s['all_configuration'] == baseline['all_configuration'] and not s['api_error'] and all(s['settings'].get(key) == baseline['settings'][key] for key in KEYS) and not s['queue'].strip() and len(s['backend']) == 2 and not [row for row in s['callbacks'] if row['state'] != '06'], 85, 'Native configuration/queue/callback state did not settle')
        client.assert_environment(proof)
    else:
        version = os.environ['NETALERTX_VERSION']
        client.assert_environment(state)
        assert len(state['backend']) == 1
        assert client.command('cat', '/app/.VERSION').strip() == 'v' + version
        catalog = json.loads(Path(__file__).with_name('vendor.json').read_text())[version]['files_sha256']
        code = "import hashlib,json,pathlib,sys;print(json.dumps({key:hashlib.sha256((pathlib.Path('/app')/key).read_bytes()).hexdigest() for key in json.loads(sys.argv[1])}))"
        actual = json.loads(client.command('python3', '-c', code, json.dumps(list(catalog))))
        assert actual == catalog
        directory = '/tmp/module-target-netalertx-native-elf'
        executable = directory + '/busybox'
        client.command('/bin/busybox', 'true')
        client.command('test', '!', '-e', directory)
        client.command('mkdir', directory)
        try:
            client.command('cp', '/bin/busybox', executable)
            client.command('chmod', '0755', executable)
            hashes = client.command('sha256sum', '/bin/busybox', executable).splitlines()
            assert hashes[0].split()[0] == hashes[1].split()[0]
            client.command(executable, 'true')
        finally:
            client.command('rm', '-f', executable)
            client.command('rmdir', directory)
        response, body = client.request('/index.php')
        assert response['status'] == 200 and 'name="loginpassword"' in body
        for password, expected in [('module-target-wrong', 200), ('module-target-netalertx-password', 302)]:
            response, _ = client.request('/index.php', {'loginpassword': password}, True)
            assert response['status'] == expected
        client.full_configuration = state['all_configuration']
        original = {key: state['settings'][key] for key in KEYS}
        values = {'DBCLNP_RUN': 'schedule', 'DBCLNP_CMD': '/bin/sh -c echo${IFS}netalertx-native:${PPID}>>/tmp/module-target-netalertx-native-proof', 'DBCLNP_RUN_SCHD': '* * * * *'}
        authenticated = version == '24.10.12'
        if authenticated:
            assert client.settings(values)['status'] == 302
            assert client.enqueue('run|DBCLNP')['status'] == 302
            assert client.enqueue('cron_restart_backend')['status'] == 302
            blocked = client.state()
            assert blocked['all_configuration'] == state['all_configuration'] and blocked['marker'] == '' and blocked['queue'] == state['queue']
        assert client.settings(values, authenticated)['status'] == 200
        client.wait(lambda s: all(s['settings'].get(key) == value for key, value in values.items()), 20, 'Native settings import did not complete')
        assert client.enqueue('run|DBCLNP', authenticated)['status'] == 200
        assert client.enqueue('cron_restart_backend', authenticated)['status'] == 200
        delivered = client.wait(lambda s: bool(s['marker']), 20, 'Native execution produced no marker')
        assert delivered['marker_uid'] == 0
        assert client.settings(original, authenticated)['status'] == 200
        initial = {(entry['pid'], entry['birth']) for entry in state['backend']}
        settled = client.wait(lambda s: not s['api_error'] and s['all_configuration'] == state['all_configuration'] and all(s['settings'].get(key) == value for key, value in original.items()) and 'cron_restart_backend' not in s['queue'] and len(s['backend']) == 2 and {(entry['pid'], entry['birth']) for entry in s['backend']} != initial, 85, 'Native cron restart/configuration restore did not settle')
        client.assert_environment(settled)
        observed = {entry['pid'] for sample in client.states for entry in sample['state']['backend']}
        marker = settled['marker'].splitlines()
        assert len(marker) == 1 and int(marker[0].rsplit(':', 1)[1]) in observed
        client.command('rm', '-f', '/tmp/module-target-netalertx-native-proof')
        proof = client.state()
        assert proof['marker'] == '' and proof['init_birth'] == state['init_birth']
        (artifacts / 'native-baseline.json').write_text(json.dumps(proof, indent=2) + '\n')
        proof = dict(proof, native_source_hashes=actual, native_marker=marker, native_version=version, native_elf_sha256=hashes[0].split()[0])
finally:
    client.write(artifacts, proof)
    source = artifacts / 'native-execution.json'
    source.replace(artifacts / ('native-execution-' + phase + '.json'))
print(json.dumps(proof))
