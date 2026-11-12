"""Start the ordinary handler's exact payload through authenticated Salt RPC."""
import base64
import hashlib
import json
from pathlib import Path
import sys

import salt.config
import salt.transport.client

payload = base64.b64decode(sys.argv[1])
family = sys.argv[2]
assert family in ('python', 'command')
code = payload.decode() if family == 'python' else 'import subprocess; subprocess.call(' + repr(payload.decode()) + ', shell=True)'
options = salt.config.minion_config('/etc/salt/minion')
options['master_uri'] = 'tcp://127.0.0.1:4506'
load = {
    'cmd': 'runner', 'fun': 'salt.cmd', 'user': 'root',
    'key': Path('/var/cache/salt/master/.root_key').read_text().strip(),
    'kwarg': {'fun': 'cmd.exec_code', 'lang': 'python', 'code': code},
}
with salt.transport.client.ReqChannel.factory(options, crypt='clear') as channel:
    reply = channel.send(load, timeout=10, tries=1)
assert 'error' not in reply, reply
print('SALT_GATHER_SDK=' + json.dumps({'status': 'sdk_dispatched',
      'payload_sha256': hashlib.sha256(payload).hexdigest(), 'reply': reply}))
