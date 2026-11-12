"""Independent real Salt CLI/API controls for post-module collection."""
import base64
import hashlib
import json
from pathlib import Path
import re
import socket
import subprocess
import sys
import time

import pkg_resources
import salt.client
import salt.config
import salt.crypt
import salt.exceptions
import salt.key
import salt.version
import yaml

configuration = json.load(sys.stdin)
state = json.loads(Path('/var/run/salt/module-target.json').read_text())
inputs = json.loads(Path('/var/run/salt/collection-inputs.json').read_text())
record = {'status': 'starting', 'calls': [], 'roles': state['roles'], 'inputs': inputs}
expected = {'module-target-minion-a', 'module-target-minion-b'}


def cli(arguments, expected_exit=None):
    try:
        result = subprocess.run(arguments, capture_output=True, timeout=120)
    except subprocess.TimeoutExpired as error:
        record['calls'].append({'argv': arguments, 'timed_out': True,
                                'stdout_base64': base64.b64encode(error.stdout or b'').decode(),
                                'stderr_base64': base64.b64encode(error.stderr or b'').decode()})
        raise
    entry = {'argv': arguments, 'exitstatus': result.returncode,
             'stdout_base64': base64.b64encode(result.stdout).decode(),
             'stderr_base64': base64.b64encode(result.stderr).decode()}
    record['calls'].append(entry)
    if expected_exit is not None:
        assert result.returncode == expected_exit, entry
    return result.stdout.decode()


try:
    assert salt.version.__version__ == '3000.1'
    record['version'] = salt.version.__version__
    installed = Path(salt.__file__).parent.parent
    record['vendor_files'] = {name: hashlib.sha256((installed / name).read_bytes()).hexdigest()
                              for name in configuration['vendor_files']}
    assert record['vendor_files'] == configuration['vendor_files']
    record['packages'] = {name: pkg_resources.get_distribution(name).version
                           for name in configuration['packages']}
    assert record['packages'] == configuration['packages']
    package = configuration['system_package']
    record['system_package'] = cli(['dpkg-query', '-W', '-f=${Version}', package['Package']], 0)
    assert record['system_package'] == package['Version']
    record['native_interfaces'] = cli(['ifconfig', '-a'], 0)
    assert Path('/etc/salt/minion').is_symlink()
    assert Path('/etc/salt/minion').resolve() == Path(state['roles']['minion-a']['config']).resolve()
    record['minion_config'] = yaml.safe_load(Path('/etc/salt/minion').read_text())
    for name, digest in inputs['files'].items():
        assert hashlib.sha256(Path(name).read_bytes()).hexdigest() == digest, name
    for name, password in [('plain', None), ('encrypted', 'module-target-key-passphrase')]:
        key = salt.crypt.get_rsa_key('/etc/salt/pki/collection/' + name + '.pem', password)
        assert key.size_in_bits() == 2048
    record['key_parse'] = {'plain': True, 'encrypted_with_fixture_passphrase': True}

    client = salt.client.get_local_client('/etc/salt/master')
    deadline = time.monotonic() + 100
    while time.monotonic() < deadline:
        try:
            ready = client.cmd('module-target-minion-*', 'test.ping', timeout=3)
            record['calls'].append({'native_api': 'test.ping', 'reply': ready})
            if set(ready) == expected and all(ready.values()):
                break
        except salt.exceptions.SaltClientError as error:
            record['calls'].append({'readiness_error': str(error)})
        time.sleep(0.2)
    else:
        raise RuntimeError('Real master and both minions were not ready')

    keys = salt.key.Key(salt.config.master_config('/etc/salt/master')).list_keys()
    record['keys'] = keys
    assert set(keys['minions']) == expected
    assert keys['minions_pre'] == ['collection-pending']
    assert keys['minions_rejected'] == ['collection-rejected']
    assert keys['minions_denied'] == ['collection-denied']
    record['cli_keys'] = yaml.safe_load(cli(['salt-key', '-L', '--output=yaml'], 0))
    assert record['cli_keys'] == keys
    # Use valid native calls as controls. The module's compound request also
    # asks for a Windows-only function; its failure is not fixture readiness.
    commands = {'hostname': 'network.get_hostname', 'ip': 'network.interfaces',
                'os': 'status.version'}
    record['collection_variants'] = {}
    for label, function in commands.items():
        argv = ['salt', '*', '--output=yaml', function]
        output = cli(argv, 0)
        parsed = yaml.safe_load(output)
        assert isinstance(parsed, dict) and set(parsed) == expected, label
        for value in parsed.values():
            if label == 'hostname':
                assert value == socket.gethostname()
            elif label == 'os':
                assert value == Path('/proc/version').read_text().strip()
            else:
                assert isinstance(value, dict) and value
                addresses = [entry['address'] for interface in value.values()
                             for entry in interface.get('inet', [])
                             if entry['address'] != '127.0.0.1']
                assert addresses and all(re.search(r'inet\s+' + re.escape(address) + r'\s', record['native_interfaces']) for address in addresses)
        record['collection_variants'][label] = parsed
    record['sls'] = cli(['salt', '*', 'state.show_sls', '*'], 0)
    assert 'module-target-state-marker' in record['sls']
    record['pillars'] = yaml.safe_load(cli(['salt', '*', '--output=yaml', 'pillar.items'], 0))
    assert set(record['pillars']) == expected
    assert all(value == inputs['pillar'] for value in record['pillars'].values())
    record['processes'] = {role: {'pid': data['pid'],
                                  'starttime': (Path('/proc') / str(data['pid']) / 'stat').read_text().split(') ', 1)[1].split()[19],
                                  'config_sha256': hashlib.sha256(Path(data['config']).read_bytes()).hexdigest()}
                            for role, data in state['roles'].items()}
    record['status'] = 'native_passed'
finally:
    print('SALT_GATHER_NATIVE=' + json.dumps(record, sort_keys=True))
