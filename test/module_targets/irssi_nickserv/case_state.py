"""Use the same real client control on an installed owning home file."""
from pathlib import Path
import base64
import hashlib
import json
import os
import pwd
import runpy
import subprocess
import sys

action, fixture, location, viewer = sys.argv[1:5]
restriction = sys.argv[5] if len(sys.argv) > 5 else 'normal'
assert restriction in ['normal', 'unreadable']
assert location in ['root', 'labuser'] and viewer in ['root', 'labuser']
catalogue = json.loads(Path('/opt/irssi-fixtures/catalogue.json').read_text())
assert fixture in catalogue
owner = pwd.getpwnam(location)
directory = Path(owner.pw_dir, '.irssi')
path = directory / 'config'
raw = Path('/opt/irssi-fixtures', fixture).read_bytes()
digest = hashlib.sha256(raw).hexdigest()
assert digest == catalogue[fixture]['sha256']
if action == 'restore':
    present = path.exists()
    if present:
        assert path.is_file() and path.read_bytes() == raw
        path.unlink()
    if directory.exists():
        assert not list(directory.iterdir())
        directory.rmdir()
    print(json.dumps({'path': str(path), 'sha256': digest, 'was_present': present, 'absent': not path.exists(), 'directory_absent': not directory.exists()}))
    raise SystemExit(0)

assert action == 'install' and not directory.exists()
directory.mkdir(mode=0o700)
os.chown(directory, owner.pw_uid, owner.pw_gid)
path.write_bytes(raw)
os.chown(path, owner.pw_uid, owner.pw_gid)
path.chmod(0o600)
sys.argv = ['/opt/irssi-fixture-native.py', 'case']
native = runpy.run_path('/opt/irssi-fixture-native.py', run_name='irssi_case_library')
native['control'](location, fixture, catalogue[fixture], config_path=str(path))
control = native['data']['controls'][-1]
assert control['identified'] == catalogue[fixture]['expected_identified']
authenticated_mode = oct(path.stat().st_mode & 0o777)
if restriction == 'unreadable':
    assert location == viewer == 'labuser'
    path.chmod(0)
reader = pwd.getpwnam(viewer)
readable = subprocess.run(['test', '-r', str(path)], user=reader.pw_uid, group=reader.pw_gid, extra_groups=[]).returncode == 0
print(json.dumps({'path': str(path), 'fixture': fixture, 'sha256': digest, 'base64': base64.b64encode(raw).decode(),
                  'uid': path.stat().st_uid, 'mode': oct(path.stat().st_mode & 0o777), 'readable': readable,
                  'file_exists': path.is_file(), 'authenticated_mode': authenticated_mode, 'restriction': restriction,
                  'expected_passwords': catalogue[fixture]['expected_passwords'], 'native_passed': True, 'native_client': control}))
