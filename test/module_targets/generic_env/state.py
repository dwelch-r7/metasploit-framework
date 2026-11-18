"""Observe selected native target state without starting a Framework module."""
from pathlib import Path
import hashlib
import json
import os
import subprocess

files = {}
for name in ['/etc/passwd', '/etc/group', '/bin/sh', '/usr/bin/env', '/opt/env_values.py', '/opt/native_probe.py']:
    path = Path(name)
    files[name] = {'sha256': hashlib.sha256(path.read_bytes()).hexdigest(),
                   'uid': path.stat().st_uid, 'mode': oct(path.stat().st_mode & 0o7777)}
homes = {name: sorted(path.name for path in Path(name).iterdir()) for name in ['/root', '/home/labuser']}
health = []
for path in Path('/proc').iterdir():
    if not path.name.isdecimal():
        continue
    try:
        arguments = (path / 'cmdline').read_bytes().split(b'\x00')
        if arguments[:5] != [b'python3', b'-m', b'http.server', b'8080', b'--bind']:
            continue
        fields = (path / 'stat').read_text().rsplit(')', 1)[1].split()
        status = (path / 'status').read_text().splitlines()
        uid = next(int(line.split()[1]) for line in status if line.startswith('Uid:'))
        assert uid == 0 and fields[0] != 'Z'
        health.append({'pid': int(path.name), 'uid': uid, 'starttime': int(fields[19]),
                       'argv': [value.decode() for value in arguments if value]})
    except FileNotFoundError:
        continue
assert len(health) == 1
owned_absence = {name: not Path(name).exists() for name in ['/run/module-target-env-case.json', '/tmp/shell-session.sh', '/tmp/meterpreter-session.elf', '/tmp/module-target-session-proof']}
assert all(owned_absence.values())
packages = subprocess.check_output(['dpkg-query', '-W', '-f=${Package}=${Version}\n', 'coreutils', 'python3'], text=True)
print(json.dumps({'files': files, 'homes': homes, 'health': health, 'owned_absence': owned_absence,
                  'packages': packages, 'hostname': os.uname().nodename, 'uid': os.geteuid()}))
