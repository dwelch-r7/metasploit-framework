"""Install and recover only the owned, native-verified credential-file fixture."""
from pathlib import Path
import hashlib
import json
import os
import pwd
import subprocess
import sys
import tempfile

action, location, fixture, user = sys.argv[1:]
assert location in ['root', 'own'] and user in ['root', 'labuser']
assert fixture in ['multiline.netrc', 'inline.netrc', 'tabs.netrc', 'comments.netrc', 'multiple.netrc', 'spaces.netrc']
account = pwd.getpwnam(user)
path = Path('/root/.netrc' if location == 'root' else account.pw_dir + '/.netrc')
assert str(path) in ['/root/.netrc', '/home/labuser/.netrc']
source = Path('/opt/netrc-fixtures', fixture).read_bytes()
sha = hashlib.sha256(source).hexdigest()

if action == 'restore':
    present = path.exists()
    if present:
        assert path.is_file() and path.read_bytes() == source
        path.unlink()
    assert not path.exists()
    print(json.dumps({'path': str(path), 'sha256': sha, 'was_present': present, 'absent': True}))
    raise SystemExit(0)

assert action == 'install' and not path.exists()
path.write_bytes(source)
owner = pwd.getpwnam('root') if location == 'root' else account
os.chown(path, owner.pw_uid, owner.pw_gid)
path.chmod(0o600)
options = {'user': account.pw_uid, 'group': account.pw_gid, 'extra_groups': []}
permissions = json.loads(subprocess.check_output([
    'python3', '-c', 'import json,os,sys;print(json.dumps({"uid":os.geteuid(),"readable":os.access(sys.argv[1],os.R_OK)}))', str(path)
], text=True, **options))
readable = location == 'own' or user == 'root'
assert permissions == {'uid': account.pw_uid, 'readable': readable}
with tempfile.TemporaryDirectory(prefix='native-netrc-case-') as directory:
    os.chmod(directory, 0o777)
    body = Path(directory) / 'body'
    args = ['curl', '-q', '--noproxy', '*', '--silent', '--show-error', '--fail', '--connect-timeout', '3',
            '--max-time', '6', '--netrc-file', str(path), '--output', str(body), '--write-out', '%{http_code}',
            'http://netrc-auth/protected/']
    result = subprocess.run(args, capture_output=True, text=True, timeout=10, **options)
    assert result.stdout == ('200' if readable else '401'), (result.returncode, result.stdout, result.stderr)
    assert result.returncode == (0 if readable else 22)
    if readable:
        assert body.read_bytes() == Path('/opt/protected-source.html').read_bytes()
assert not Path(directory).exists()
info = path.stat()
print(json.dumps({'path': str(path), 'fixture': fixture, 'sha256': sha, 'uid': info.st_uid,
                  'gid': info.st_gid, 'mode': oct(info.st_mode & 0o777), 'permissions': permissions,
                  'native_client': {'argv': args, 'exit': result.returncode, 'http_status': int(result.stdout),
                                    'stderr': result.stderr}, 'native_passed': True}))
