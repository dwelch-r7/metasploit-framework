"""Create real collection inputs, then run the unchanged Salt supervisor."""
import hashlib
import json
import os
from pathlib import Path
import sys

import salt.crypt
import yaml


def main():
    # This default path aliases the exact generated config used by minion A.
    # It is not a stand-in client config presented as daemon configuration.
    default = Path('/etc/salt/minion')
    default.unlink()
    default.symlink_to('/var/run/salt/minion-a-config/minion')

    keys = Path('/etc/salt/pki/collection')
    keys.mkdir(mode=0o700)
    salt.crypt.gen_keys(str(keys), 'plain', 2048)
    salt.crypt.gen_keys(str(keys), 'encrypted', 2048,
                        passphrase='module-target-key-passphrase')
    roster = {
        'collection-password': {'host': '192.0.2.10', 'port': 2222, 'user': 'root',
                                'passwd': 'module-target-inventory-password'},
        'collection-key': {'host': '192.0.2.11', 'user': 'root',
                           'priv': str(keys / 'plain.pem')},
        'collection-key-reuse': {'host': '192.0.2.12', 'user': 'root',
                                 'priv': str(keys / 'plain.pem')},
        'collection-encrypted': {'host': '192.0.2.13', 'user': 'root',
                                 'priv': str(keys / 'encrypted.pem'),
                                 'priv_passwd': 'module-target-key-passphrase'},
    }
    Path('/etc/salt/roster').write_text(yaml.safe_dump(roster))
    # These are valid Salt public keys in the native administrative stores.
    # They exercise listing, not authentication of additional fake daemons.
    for directory, name in [('minions_pre', 'collection-pending'),
                            ('minions_rejected', 'collection-rejected'),
                            ('minions_denied', 'collection-denied')]:
        location = Path('/etc/salt/pki/master') / directory
        location.mkdir(parents=True, exist_ok=True)
        (location / name).write_bytes((keys / 'plain.pub').read_bytes())

    Path('/srv/salt/collection.sls').write_text(
        'collection_reference:\n  test.nop:\n    - name: module-target-state-marker\n')
    Path('/srv/pillar/top.sls').write_text("base:\n  '*':\n    - collection\n")
    pillar = {'module_target': {'marker': 'module-target-pillar-marker',
                                'nested': {'enabled': True, 'number': 17}}}
    Path('/srv/pillar/collection.sls').write_text(yaml.safe_dump(pillar))
    files = ['/etc/salt/roster', '/srv/salt/collection.sls',
             '/srv/pillar/top.sls', '/srv/pillar/collection.sls']
    files += [str(path) for path in sorted(keys.iterdir())]
    record = {'roster': roster, 'pillar': pillar,
              'files': {name: hashlib.sha256(Path(name).read_bytes()).hexdigest()
                        for name in files},
              'default_minion_alias': str(default),
              'default_minion_target': str(default.resolve(strict=False))}
    Path('/var/run/salt/collection-inputs.json').write_text(json.dumps(record))
    os.execv(sys.executable, [sys.executable, '/opt/module-target/session-target.py'])


if __name__ == '__main__':
    main()
