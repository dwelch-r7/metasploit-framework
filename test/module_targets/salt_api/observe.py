"""Observe original Salt sources, files and ordinary daemon configuration."""

from pathlib import Path
import base64
import hashlib
import json
import os
import re
import shutil
import stat
import sys

import cherrypy
import salt
import salt.version


def metadata():
    root = Path(salt.__file__).parent
    names = ['netapi/__init__.py', 'netapi/rest_cherrypy/__init__.py', 'netapi/rest_cherrypy/app.py', 'client/ssh/__init__.py', 'client/ssh/shell.py', 'client/ssh/client.py', 'auth/sharedsecret.py']
    return dict(uid=os.geteuid(), python=sys.version, salt=salt.version.__version__, cherrypy=cherrypy.__version__, tools={name: shutil.which(name) for name in ['ssh', 'ssh-keygen', 'openssl', 'bash', 'curl', 'wget']}, files_sha256={name: hashlib.sha256((root/name).read_bytes()).hexdigest() for name in names})


def snapshot():
    runtime = json.loads(Path('/var/run/salt/module-target-api.json').read_text())
    names = [path for role in runtime['roles'].values() for path in [Path(role['config']), Path(role['config']).parent/'roster']] + [Path('/etc/salt/roster'), Path('/var/run/salt/api.crt'), Path('/var/run/salt/api.key')]
    device = os.stat('/dev/null')
    return dict(files={str(path): hashlib.sha256(path.read_bytes()).hexdigest() for path in names}, dev_null=dict(mode=device.st_mode, uid=device.st_uid, gid=device.st_gid, rdev=device.st_rdev), runtime=runtime)


def proof(path, remove):
    assert re.fullmatch(r'/tmp/module-target-saltapi-[a-zA-Z0-9_.-]+', path)
    target = Path(path)
    if remove and target.exists():
        target.unlink()
    return dict(exists=True, uid=target.stat().st_uid, base64=base64.b64encode(target.read_bytes()).decode()) if target.exists() else dict(exists=False)


def artifacts(remove=False):
    root = Path('/dev/null < ')
    if not root.exists():
        return dict(exists=False)
    assert root.is_dir() and not root.is_symlink()
    rows = []
    for path in sorted(root.rglob('*')):
        details = path.lstat()
        rows.append(dict(path=str(path), mode=details.st_mode, uid=details.st_uid, type='directory' if stat.S_ISDIR(details.st_mode) else 'other'))
    if remove:
        shutil.rmtree(str(root))
        assert not root.exists()
    return dict(exists=True, rows=rows, removed=remove)


action, *arguments = sys.argv[1:]
if action == 'metadata':
    result = metadata()
elif action == 'snapshot':
    result = snapshot()
elif action == 'proof':
    result = proof(arguments[0], arguments[1:] == ['remove'])
elif action == 'artifacts':
    result = artifacts(arguments == ['remove'])
else:
    raise ValueError('Unsupported observation action')
print(json.dumps(result))
