"""Use the vendor's clear ZeroMQ client to verify the real master listener."""
import salt.config
import salt.transport.client

options = salt.config.minion_config('/etc/salt/minion')
# Salt's minion daemon normally resolves this before constructing its channel.
options['master_uri'] = 'tcp://127.0.0.1:4506'
with salt.transport.client.ReqChannel.factory(options, crypt='clear') as channel:
    assert channel.send({'cmd': 'ping'}, timeout=3, tries=1) == {'cmd': 'ping'}
