"""Install genuine account-home keyrings and recover only recorded files."""
from pathlib import Path
import base64
import hashlib
import json
import os
import pwd
import runpy
import shutil
import subprocess
import sys

state = Path('/run/module-target-gpg-case.json')
action = sys.argv[1]
assert action in ['install', 'restore', 'missing']
if action == 'missing':
    assert not state.exists()
    homes = {account.pw_dir for account in pwd.getpwall()} | {str(path) for path in Path('/home').iterdir()}
    checked = sorted(str(Path(home) / '.gnupg') for home in homes)
    assert not any(Path(path).exists() for path in checked)
    print(json.dumps({'native_passed': True, 'missing': True, 'checked_paths': checked, 'files': {}}))
    raise SystemExit(0)
if action == 'restore':
    if not state.exists():
        print(json.dumps({'absent': True, 'was_present': False}))
        raise SystemExit(0)
    data = json.loads(state.read_text())
    account = pwd.getpwnam(data['holder'])
    home = Path(data['home'])
    assert home == Path(account.pw_dir) / '.gnupg' and not home.is_symlink()
    actual = {str(path.relative_to(home)): path for path in home.rglob('*') if path.is_file()}
    assert actual.keys() == data['files'].keys()
    for name, path in actual.items():
        expected = data['files'][name]
        assert hashlib.sha256(path.read_bytes()).hexdigest() == expected['sha256']
        assert path.stat().st_uid == expected['uid'] and oct(path.stat().st_mode & 0o777) == expected['mode']
    native = runpy.run_path('/opt/fixture_native.py', run_name='gpg_case_library')
    assert not native['agents'](home, account.pw_uid)
    shutil.rmtree(home)
    assert state.stat().st_uid == 0 and state.stat().st_mode & 0o777 == 0o600
    state.unlink()
    print(json.dumps({'absent': not home.exists() and not state.exists(), 'was_present': True}))
    raise SystemExit(0)

holder, viewer, protection, restriction, empty = sys.argv[2:7]
assert holder in ['root', 'labuser'] and viewer in ['root', 'labuser']
assert protection in ['plain', 'protected'] and restriction in ['normal', 'unreadable'] and empty in ['empty', 'noempty']
assert not state.exists()
account = pwd.getpwnam(holder)
reader = pwd.getpwnam(viewer)
home = Path(account.pw_dir) / '.gnupg'
assert not home.exists()
native = runpy.run_path('/opt/fixture_native.py', run_name='gpg_case_library')
native['control'](holder, protection == 'protected', homedir=str(home), keep=True)
control = native['data']['controls'][-1]
assert control['native_passed'] and control['home_retained_for_owning_case']
data = {'holder': holder, 'viewer': viewer, 'home': str(home), 'native_control': control, 'files': {}}
if empty == 'empty':
    path = home / 'empty-record'
    path.write_bytes(b'')
    os.chown(path, account.pw_uid, account.pw_gid)
    path.chmod(0o600)
if restriction == 'unreadable':
    assert holder == viewer == 'labuser'
    (home / 'private-keys-v1.d' / (control['keygrip'] + '.key')).chmod(0)
for path in sorted(home.rglob('*')):
    if not path.is_file():
        assert path.is_dir() and not path.is_symlink()
        continue
    relative = str(path.relative_to(home))
    raw = path.read_bytes()
    readable = subprocess.run(['test', '-r', str(path)], user=reader.pw_uid, group=reader.pw_gid, extra_groups=[]).returncode == 0
    direct = len(path.relative_to(home).parts) == 1 or path.parent == home / 'private-keys-v1.d'
    data['files'][relative] = {'path': str(path), 'bytes': len(raw), 'base64': base64.b64encode(raw).decode(),
                              'sha256': hashlib.sha256(raw).hexdigest(), 'uid': path.stat().st_uid,
                              'mode': oct(path.stat().st_mode & 0o777), 'readable': readable,
                              'expected_collect': direct and bool(raw) and readable,
                              'origin': 'synthetic empty boundary' if relative == 'empty-record' else 'native GnuPG file'}
state.write_text(json.dumps(data, indent=2) + '\n')
state.chmod(0o600)
data['native_passed'] = True
print(json.dumps(data))
