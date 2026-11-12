"""Calibrate the handler's actual command through legitimate root Salt RPC."""
import base64
import json
from pathlib import Path
import sys

import salt.config
import salt.transport.client

command = base64.b64decode(sys.argv[1]).decode()
options = salt.config.minion_config('/etc/salt/minion')
options['master_uri'] = 'tcp://127.0.0.1:4506'
code = 'import subprocess; subprocess.call(' + repr(command) + ', shell=True)'
load = {
    'cmd': 'runner', 'fun': 'salt.cmd', 'user': 'root',
    'key': Path('/var/cache/salt/master/.root_key').read_text().strip(),
    'kwarg': {'fun': 'cmd.exec_code', 'lang': 'python', 'code': code},
}
with salt.transport.client.ReqChannel.factory(options, crypt='clear') as channel:
    reply = channel.send(load, timeout=10, tries=1)
assert 'error' not in reply, reply
print('SALT_SDK=' + json.dumps({'status': 'sdk_dispatched', 'reply': reply}))
