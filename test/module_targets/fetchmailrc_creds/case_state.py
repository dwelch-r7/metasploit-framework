"""Authenticate an exact home file before collecting it; recover only its bytes."""
from pathlib import Path
import base64
import hashlib
import json
import os
import pwd
import subprocess
import sys
import tempfile
import time

action, fixture, location, viewer = sys.argv[1:]
catalogue = json.loads(Path('/opt/fetchmail-fixtures/catalogue.json').read_text())
assert fixture in catalogue and location in ['root', 'labuser'] and viewer in ['root', 'labuser']
owner = pwd.getpwnam(location)
path = Path(owner.pw_dir, '.fetchmailrc')
raw = Path('/opt/fetchmail-fixtures', fixture).read_bytes()
digest = hashlib.sha256(raw).hexdigest()
assert digest == catalogue[fixture]['sha256']
if action == 'restore':
    present = path.exists()
    if present:
        assert path.is_file() and path.read_bytes() == raw
        path.unlink()
    assert not path.exists()
    print(json.dumps({'path': str(path), 'was_present': present, 'absent': True, 'sha256': digest}))
    raise SystemExit(0)

assert action == 'install' and not path.exists()
path.write_bytes(raw)
os.chown(path, owner.pw_uid, owner.pw_gid)
path.chmod(0o600)
log = Path('/tmp/dovecot-module-target.log')
offset = log.stat().st_size
with tempfile.TemporaryDirectory(prefix='fetchmail-home-proof-') as directory:
    os.chown(directory, owner.pw_uid, owner.pw_gid)
    env = {key: value for key, value in os.environ.items() if not key.startswith('FETCHMAIL')}
    env.update(HOME=directory, FETCHMAILHOME=directory, USER=location, LOGNAME=location, LC_ALL='C')
    args = ['fetchmail', '--check', '--nodetach', '--nosyslog', '--verbose', '-f', str(path)]
    result = subprocess.run(args, env=env, capture_output=True, text=True, timeout=40,
                            user=owner.pw_uid, group=owner.pw_gid, extra_groups=[])
    assert result.returncode == 0, (result.returncode, result.stderr)
assert not Path(directory).exists()
accounts = catalogue[fixture]['accounts']
deadline = time.monotonic() + 3
while True:
    observed = log.read_bytes()[offset:].decode(errors='replace')
    if all('Login: user=<' + item['user'] + '>' in observed for item in accounts):
        break
    assert time.monotonic() < deadline, observed
    time.sleep(0.05)
reader = pwd.getpwnam(viewer)
readable = subprocess.run(['test', '-r', str(path)], user=reader.pw_uid, group=reader.pw_gid, extra_groups=[]).returncode == 0
print(json.dumps({'path': str(path), 'fixture': fixture, 'sha256': digest, 'base64': base64.b64encode(raw).decode(),
                  'uid': path.stat().st_uid, 'mode': oct(path.stat().st_mode & 0o777), 'readable': readable,
                  'expected': accounts, 'native_passed': True,
                  'native_client': {'argv': args, 'exit': result.returncode, 'stdout': result.stdout,
                                    'stderr': result.stderr, 'native_server_log': observed}}))
