"""Verify installed Salt bytes and the actual executing daemon independently."""
import hashlib
import json
import os
from pathlib import Path
import socket
import sys

import pkg_resources
import salt.version
import yaml

configuration = json.load(sys.stdin)
state = json.loads(Path('/var/run/salt/deployment-role.json').read_text())
installed = Path(salt.__file__).parent.parent
process = Path('/proc') / str(state['pid'])
record = {'state': state, 'version': salt.version.__version__,
          'hostname': socket.gethostname(), 'uid': os.getuid(),
          'mount_namespace': os.readlink('/proc/1/ns/mnt'),
          'config': yaml.safe_load(Path(state['config']).read_text()),
          'process_starttime': (process / 'stat').read_text().split(') ', 1)[1].split()[19],
          'vendor_files': {name: hashlib.sha256((installed / name).read_bytes()).hexdigest()
                           for name in configuration['vendor_files']},
          'packages': {name: pkg_resources.get_distribution(name).version
                        for name in configuration['packages']}}
assert record['version'] == '3000.1' and record['uid'] == 0
assert record['vendor_files'] == configuration['vendor_files']
assert record['packages'] == configuration['packages']
assert hashlib.sha256(Path(state['config']).read_bytes()).hexdigest() == state['config_sha256']
environment = dict(item.split(b'=', 1) for item in (process / 'environ').read_bytes().split(bytes([0])) if b'=' in item)
assert environment[b'MSF_MODULE_TARGET_TOKEN'].decode() == state['token']
assert environment[b'MSF_MODULE_TARGET_ROLE'].decode() == state['role']
record['status'] = 'native_identity_passed'
print('SALT_DEPLOY_IDENTITY=' + json.dumps(record, sort_keys=True))
