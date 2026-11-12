"""Run one genuine Salt daemon per isolated filesystem and execution identity."""
import hashlib
import json
import os
from pathlib import Path
import uuid

import yaml

role = os.environ['SALT_DEPLOY_ROLE']
assert role in ('master', 'minion-a', 'minion-b')
token = uuid.uuid4().hex
os.environ['MSF_MODULE_TARGET_ROLE'] = role
os.environ['MSF_MODULE_TARGET_TOKEN'] = token
if role != 'master':
    options = yaml.safe_load(Path('/etc/salt/minion').read_text())
    options.update(master='master', id='module-target-' + role,
                   cachedir='/var/cache/salt/minion', pki_dir='/etc/salt/pki/minion',
                   sock_dir='/var/run/salt/minion', pidfile='/var/run/salt/minion.pid',
                   log_file='/var/log/salt/minion', acceptance_wait_time=1,
                   acceptance_wait_time_max=2)
    Path('/etc/salt/minion').write_text(yaml.safe_dump(options))
config = '/etc/salt/master' if role == 'master' else '/etc/salt/minion'
executable = 'salt-master' if role == 'master' else 'salt-minion'
state = {'role': role, 'token': token, 'pid': os.getpid(), 'config': config,
         'config_sha256': hashlib.sha256(Path(config).read_bytes()).hexdigest()}
Path('/var/run/salt/deployment-role.json').write_text(json.dumps(state))
os.execvp(executable, [executable, '--log-level=warning', '--config-dir=/etc/salt'])
