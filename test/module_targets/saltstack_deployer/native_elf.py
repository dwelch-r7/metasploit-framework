"""Calibrate an exact handler ELF through legitimate Salt deployment APIs."""
import base64
import hashlib
import json
from pathlib import Path
import subprocess
import sys

import salt.client

configuration = json.load(sys.stdin)
record = {'status': 'starting'}
try:
    executable = base64.b64decode(configuration['executable_base64'])
    assert executable.startswith(b'\x7fELF')
    assert hashlib.sha256(executable).hexdigest() == configuration['executable_sha256']
    source = Path(configuration['source'])
    encoded = base64.b64encode(executable)
    source.write_bytes(encoded)
    result = subprocess.run(['salt-cp', configuration['selector'], str(source), configuration['destination'] + '.b64'], capture_output=True, timeout=120)
    record['copy'] = {'exitstatus': result.returncode,
                      'stdout_base64': base64.b64encode(result.stdout).decode(),
                      'stderr_base64': base64.b64encode(result.stderr).decode()}
    assert result.returncode == 0
    client = salt.client.get_local_client('/etc/salt/master')
    command = 'base64 -d {path}.b64 > {path} && chmod 755 {path} && {path}'.format(path=configuration['destination'])
    record['jid'] = client.cmd_async(configuration['selector'], 'cmd.run', [command])
    assert isinstance(record['jid'], str) and record['jid'].isdigit()
    record['status'] = 'native_elf_dispatched'
finally:
    print('SALT_DEPLOY_ELF=' + json.dumps(record, sort_keys=True))
