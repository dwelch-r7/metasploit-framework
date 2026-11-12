"""Check daemon identity; native controls separately prove encrypted minion RPC."""
import json
from pathlib import Path

state = json.loads(Path('/var/run/salt/deployment-role.json').read_text())
process = Path('/proc') / str(state['pid'])
command = (process / 'cmdline').read_bytes()
assert ('salt-master' if state['role'] == 'master' else 'salt-minion').encode() in command
assert (process / 'stat').read_text().split(') ', 1)[1].split()[0] != 'Z'
if state['role'] == 'master':
    import salt.config
    import salt.transport.client
    options = salt.config.minion_config('/etc/salt/minion')
    options['master_uri'] = 'tcp://127.0.0.1:4506'
    with salt.transport.client.ReqChannel.factory(options, crypt='clear') as channel:
        assert channel.send({'cmd': 'ping'}, timeout=3, tries=1) == {'cmd': 'ping'}
