"""Run a task-owned generated payload; never invokes a network exploitation stub."""
import json
import os
import pwd
from pathlib import Path
import shutil
import subprocess
import sys

source = Path(sys.argv[1]).resolve(strict=True)
assert source.parent == Path('/opt/module-target-artifacts'), source
assert source.name in ('shell-session.elf', 'meterpreter-session.elf'), source
target = Path('/tmp') / source.name
shutil.copyfile(source, target)
target.chmod(0o700)
user = sys.argv[2] if len(sys.argv) > 2 else 'root'
assert user in ('root', 'labuser'), user
identity = pwd.getpwnam(user)
os.chown(target, identity.pw_uid, identity.pw_gid)
environment = os.environ.copy()
environment.update(HOME=identity.pw_dir, USER=user, LOGNAME=user)
argv = [str(target)]
with open('/tmp/module-target-session.log', 'ab', buffering=0) as log:
    process = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=log,
                               stderr=subprocess.STDOUT, start_new_session=True,
                               user=identity.pw_uid, group=identity.pw_gid,
                               extra_groups=[], env=environment)
print(json.dumps(dict(pid=process.pid, path=str(target), argv=argv)))
