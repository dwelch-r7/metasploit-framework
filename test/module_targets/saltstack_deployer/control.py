"""Use real Salt RPC and salt-cp for native file deployment controls."""
import base64
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import time

import salt.client
import salt.exceptions
import salt.key
import salt.config

configuration = json.load(sys.stdin)
record = {'status': 'starting', 'calls': []}
expected = {'module-target-minion-a', 'module-target-minion-b'}
client = salt.client.get_local_client('/etc/salt/master')


def call_cli(arguments):
    result = subprocess.run(arguments, capture_output=True, timeout=120)
    entry = {'argv': arguments, 'exitstatus': result.returncode,
             'stdout_base64': base64.b64encode(result.stdout).decode(),
             'stderr_base64': base64.b64encode(result.stderr).decode()}
    record['calls'].append(entry)
    assert result.returncode == 0, entry


try:
    deadline = time.monotonic() + 180
    while time.monotonic() < deadline:
        try:
            replies = client.cmd('module-target-minion-*', 'test.ping', timeout=3)
            record['calls'].append({'native_api': 'test.ping', 'reply': replies})
            if set(replies) == expected and all(replies.values()):
                break
        except salt.exceptions.SaltClientError as error:
            record['calls'].append({'readiness_error': str(error)})
        time.sleep(0.2)
    else:
        raise RuntimeError('Master and both independent minions were not ready')
    record['keys'] = salt.key.Key(salt.config.master_config('/etc/salt/master')).list_keys()
    assert set(record['keys']['minions']) == expected
    record['deployments'] = []
    for case in configuration['cases']:
        source = Path(case['source'])
        raw = base64.b64decode(case['bytes_base64'])
        source.write_bytes(raw)
        source.chmod(0o755)
        call_cli(['salt-cp', case['selector'], str(source), case['encoded_destination']])
        # Use the same decode/chmod/execute sequence as the owning module.
        command = 'base64 -d {encoded} > {executable} && chmod 755 {executable} && {executable}'.format(
            encoded=case['encoded_destination'], executable=case['executable_destination'])
        replies = client.cmd(case['selector'], 'cmd.run', [command], timeout=30)
        wanted = expected if case['selector'] == '*' else {case['selector']}
        assert set(replies) == wanted, replies
        for node, output in replies.items():
            role = node[len('module-target-'):]
            assert 'SALT_DEPLOY_ROLE=' + role in output, output
            assert 'SALT_DEPLOY_TOKEN=' + configuration['tokens'][role] in output, output
            assert output.strip().endswith('SALT_DEPLOY_UID=0'), output
        record['deployments'].append({'case': case['name'], 'selector': case['selector'],
                                      'source_sha256': hashlib.sha256(source.read_bytes()).hexdigest(),
                                      'replies': replies})
    record['status'] = 'native_deployment_passed'
finally:
    print('SALT_DEPLOY_NATIVE=' + json.dumps(record, sort_keys=True))
