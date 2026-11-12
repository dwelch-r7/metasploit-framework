"""Exercise the installed vendor client and genuine master, independently of MSF."""
import hashlib
import json
from pathlib import Path
import platform
import sys
import time

import pkg_resources
import salt
import salt.config
import salt.payload
import salt.transport.client
import salt.version
import zmq

configuration = json.load(sys.stdin)
version = configuration['version']
options = salt.config.minion_config('/etc/salt/minion')
options['master_uri'] = 'tcp://127.0.0.1:4506'
record = {'status': 'starting', 'version': salt.version.__version__,
          'python': platform.python_version(), 'pyzmq': zmq.__version__,
          'libzmq': zmq.zmq_version(), 'requests': []}


def send(load):
    with salt.transport.client.ReqChannel.factory(options, crypt='clear') as channel:
        reply = channel.send(load, timeout=10, tries=1)
    return reply


try:
    assert record['version'] == version
    assert record['python'] == '3.7.17'
    assert (record['pyzmq'], record['libzmq']) == ('19.0.2', '4.3.2')
    installed = Path(salt.__file__).parent.parent
    record['vendor_files'] = {
        name: hashlib.sha256((installed / name).read_bytes()).hexdigest()
        for name in configuration['vendor_files']
    }
    assert record['vendor_files'] == configuration['vendor_files']
    record['packages'] = {
        name: pkg_resources.get_distribution(name).version
        for name in configuration['packages']
    }
    assert record['packages'] == configuration['packages']
    record['fixture_files'] = {name: hashlib.sha256(Path(name).read_bytes()).hexdigest()
                               for name in configuration['fixture_files']}
    assert record['fixture_files'] == configuration['fixture_files']
    keyfile = Path('/var/cache/salt/master/.root_key')
    key = keyfile.read_text().strip()
    record['root_key_sha256'] = hashlib.sha256(key.encode()).hexdigest()
    record['identity'] = Path('/proc/1/stat').read_text().split(') ', 1)[1].split()[19]
    record['command'] = Path('/proc/1/cmdline').read_bytes().replace(b'\0', b' ').decode()
    assert record['command'].startswith('/usr/local/bin/python /usr/local/bin/salt-master ')
    assert send({'cmd': 'ping'}) == {'cmd': 'ping'}
    record['requests'].append({'method': 'ping', 'reply': {'cmd': 'ping'}})
    reply = send({'cmd': '_prep_auth_info'})
    record['auth_info_bytes'] = len(salt.payload.Serial(options).dumps(reply))
    if version == '3000.1':
        assert reply[:2] == ['user', 'UserAuthenticationError']
        assert reply[2]['root'] == key
        assert sorted(reply[2]) == configuration['expected_users']
        disclosure = {'users': sorted(reply[2]), 'key_matches_master': True}
    else:
        assert reply == {}, reply
        disclosure = reply
    record['requests'].append({'method': '_prep_auth_info', 'reply': disclosure})

    # Authenticate a real runner job using the local master's generated key.
    # The rejected request must not run the same command or create its marker.
    marker = Path('/tmp/module-target-native-runner-' + configuration['phase'])
    assert not marker.exists()
    # `cmd` is a reserved runner-client keyword in this Salt release. Use the
    # documented execution-code arguments rather than losing cmd.run's input.
    code = 'open(' + repr(str(marker)) + ', "w").write("native-salt-control")'
    load = {'cmd': 'runner', 'fun': 'salt.cmd', 'user': 'root',
            'kwarg': {'fun': 'cmd.exec_code', 'lang': 'python', 'code': code}}
    try:
        rejected = send(dict(load, key='module-target-invalid-root-key'))
        assert rejected['error']['name'] == 'UserAuthenticationError', rejected
        assert not marker.exists()
        record['requests'].append({'method': 'runner', 'key': 'rejected', 'reply': rejected})
        accepted = send(dict(load, key=key))
        assert 'error' not in accepted, accepted
        record['requests'].append({'method': 'runner', 'key': 'accepted', 'reply': accepted})
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline and not marker.exists():
            time.sleep(0.2)
        assert marker.read_text() == 'native-salt-control'
        record['authenticated_runner_executed'] = True
        # Preserve the actual job result instead of treating a returned JID as
        # proof that an asynchronous command completed successfully.
        completed = []
        while time.monotonic() < deadline:
            returns = Path('/var/cache/salt/master/jobs').rglob('return.p')
            record['job_returns'] = [salt.payload.Serial(options).loads(path.read_bytes()) for path in returns]
            completed = [job['return'] for job in record['job_returns']
                         if job['return']['jid'] == accepted['jid']]
            if completed:
                break
            time.sleep(0.2)
        assert len(completed) == 1 and completed[0]['success'] is True, record['job_returns']
    finally:
        if marker.exists():
            marker.unlink()
    assert not marker.exists()
    record['status'] = 'native_passed'
finally:
    print(json.dumps(record, sort_keys=True))
