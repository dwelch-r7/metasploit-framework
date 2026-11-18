"""Snapshot selected system, home and native health-service identity."""
from pathlib import Path
import hashlib
import json
import os
import subprocess

names = ['/etc/passwd', '/etc/group', '/usr/bin/gpg', '/usr/bin/gpgconf', '/usr/bin/gpg-agent', '/opt/fixture_native.py', '/opt/artifacts.py', '/opt/launch_session.py', '/opt/shared-launch-session.py', '/opt/process-state.py', '/opt/descendants.py', '/opt/env_values.py', '/opt/native_probe.py', '/opt/gpg-case-state.py']
files = {name: {'sha256': hashlib.sha256(Path(name).read_bytes()).hexdigest(),
                 'uid': Path(name).stat().st_uid, 'mode': oct(Path(name).stat().st_mode & 0o7777)} for name in names}
assert Path('/opt/module-target-artifacts').is_dir()
assert not any(Path('/tmp').glob('module-target-druid-session-*'))
assert not any(Path('/tmp', name).exists() for name in ['shell-session.sh', 'meterpreter-session.elf'])
homes = {name: sorted(path.name for path in Path(name).iterdir()) for name in ['/root', '/home/lab space']}
health = []
for path in Path('/proc').iterdir():
    if not path.name.isdecimal():
        continue
    try:
        arguments = (path / 'cmdline').read_bytes().split(b'\x00')
        if arguments[:5] != [b'python3', b'-m', b'http.server', b'8080', b'--bind']:
            continue
        fields = (path / 'stat').read_text().rsplit(')', 1)[1].split()
        health.append({'pid': int(path.name), 'starttime': int(fields[19]), 'argv': [item.decode() for item in arguments if item]})
    except FileNotFoundError:
        continue
assert len(health) == 1
assert not Path('/root/.gnupg').exists() and not Path('/home/lab space/.gnupg').exists()
assert not Path('/run/module-target-gpg-case.json').exists()
assert not Path('/run/module-target-env-case.json').exists()
packages = subprocess.check_output(['dpkg-query', '-W', '-f=${Package}=${Version}\n', 'gnupg', 'gpg', 'gpg-agent', 'gpgconf', 'python3'], text=True)
print(json.dumps({'files': files, 'homes': homes, 'health': health, 'packages': packages,
                  'hostname': os.uname().nodename, 'uid': os.geteuid()}))
