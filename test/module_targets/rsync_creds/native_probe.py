"""Read actual target state and authenticate through the native rsync client."""
from pathlib import Path
import base64
import hashlib
import json
import os
import pwd
import subprocess
import tempfile

paths = ['/etc/rsyncd.conf', '/root/rsyncd.conf', '/root/rsync-user.conf', '/etc/rsyncd.secrets', '/srv/share/proof.txt', '/etc/passwd']
files = {}
for value in paths:
    path = Path(value)
    raw = path.read_bytes()
    info = path.stat()
    files[value] = {'sha256': hashlib.sha256(raw).hexdigest(), 'bytes': len(raw), 'mode': oct(info.st_mode & 0o777), 'uid': info.st_uid, 'gid': info.st_gid, 'base64': base64.b64encode(raw).decode()}
assert files['/etc/rsyncd.secrets']['mode'] == '0o600'
assert files['/etc/rsyncd.secrets']['uid'] == 0
assert Path('/etc/rsyncd.secrets').read_bytes() == b'labuser:labpassword\n'
assert Path('/srv/share/proof.txt').read_bytes() == b'rsync-module-target-proof\n'
assert files['/etc/rsyncd.conf']['sha256'] == files['/root/rsyncd.conf']['sha256']
assert files['/etc/rsyncd.conf']['sha256'] == files['/root/rsync-user.conf']['sha256']
assert not Path('/etc/module-target-rsync-missing.conf').exists()
client = []
for user in ['root', 'labuser']:
    account = pwd.getpwnam(user)
    options = {'user': account.pw_uid, 'group': account.pw_gid, 'extra_groups': []}
    code = 'import json,os;print(json.dumps({"uid":os.geteuid(),"config_readable":os.access("/etc/rsyncd.conf",os.R_OK),"home_config_readable":os.access("/root/rsyncd.conf",os.R_OK),"secrets_readable":os.access("/etc/rsyncd.secrets",os.R_OK)}))'
    permissions = json.loads(subprocess.check_output(['python3', '-c', code], text=True, **options))
    assert permissions['uid'] == account.pw_uid and permissions['config_readable']
    assert permissions['secrets_readable'] == (user == 'root')
    assert permissions['home_config_readable'] == (user == 'root')
    for label, password, success in [('valid', 'labpassword', True), ('wrong', 'module-target-wrong-password', False)]:
        env = dict(os.environ, RSYNC_PASSWORD=password, HOME=account.pw_dir)
        args = ['rsync', '--contimeout=3', '--timeout=3', '--no-motd', '--list-only', 'rsync://labuser@127.0.0.1/locked/']
        result = subprocess.run(args, env=env, capture_output=True, text=True, timeout=8, **options)
        if success:
            assert result.returncode == 0 and 'proof.txt' in result.stdout, (result.returncode, result.stderr)
        else:
            assert result.returncode != 0 and 'auth failed' in result.stderr.lower(), (result.returncode, result.stderr)
        client.append({'user': user, 'uid': account.pw_uid, 'case': label, 'argv': args, 'exit': result.returncode, 'stdout': result.stdout, 'stderr': result.stderr, 'permissions': permissions})
with tempfile.TemporaryDirectory(prefix='module-target-rsync-native-') as directory:
    destination = Path(directory) / 'proof.txt'
    result = subprocess.run(['rsync', '--contimeout=3', '--timeout=3', '--no-motd', 'rsync://labuser@127.0.0.1/locked/proof.txt', str(destination)], env=dict(os.environ, RSYNC_PASSWORD='labpassword'), capture_output=True, text=True, timeout=8)
    assert result.returncode == 0 and destination.read_bytes() == Path('/srv/share/proof.txt').read_bytes(), (result.returncode, result.stderr)
    download = {'exit': result.returncode, 'bytes': destination.stat().st_size, 'sha256': hashlib.sha256(destination.read_bytes()).hexdigest(), 'temporary_directory': directory}
assert not Path(download['temporary_directory']).exists()
pid = int(Path('/tmp/module-target-rsyncd.pid').read_text())
command = Path('/proc', str(pid), 'cmdline').read_bytes().replace(b'\0', b' ').decode().strip()
assert 'rsync --daemon --no-detach --config /etc/rsyncd.conf' in command
packages = subprocess.check_output(['dpkg-query', '-W', '-f=${Package}=${Version}\n', 'rsync', 'python3'], text=True)
assert 'rsync=3.2.7-0ubuntu0.22.04.7' in packages
print(json.dumps({'hostname': subprocess.check_output(['hostname'], text=True).strip(), 'uid': os.geteuid(), 'os_release': Path('/etc/os-release').read_text(), 'rsync_version': subprocess.check_output(['rsync', '--version'], text=True), 'packages': packages, 'files': files, 'client_authentication': client, 'download': download, 'daemon': {'pid': pid, 'command': command}, 'native_passed': True}, indent=2))
