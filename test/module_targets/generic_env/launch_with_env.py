"""Supply controlled target values to the unchanged genuine ELF launcher."""
from pathlib import Path
import json
import os
import pwd
import runpy
import shutil
import subprocess
import sys

from env_values import environment_for

user = sys.argv[2] if len(sys.argv) > 2 else 'root'
variant = json.loads(Path('/run/module-target-env-case.json').read_text())['variant']
values = environment_for(user, variant)
os.environ.clear()
os.environ.update(values)
if Path(sys.argv[1]).name == 'shell-session.sh':
    source = Path(sys.argv[1]).resolve(strict=True)
    assert source.parent == Path('/opt/module-target-artifacts')
    target = Path('/tmp/shell-session.sh')
    shutil.copyfile(source, target)
    account = pwd.getpwnam(user)
    os.chown(target, account.pw_uid, account.pw_gid)
    target.chmod(0o700)
    with open('/tmp/module-target-session.log', 'ab', buffering=0) as log:
        process = subprocess.Popen(['/bin/sh', str(target)], stdin=subprocess.DEVNULL,
                                   stdout=log, stderr=subprocess.STDOUT, start_new_session=True,
                                   user=account.pw_uid, group=account.pw_gid, extra_groups=[], env=values)
    print(json.dumps({'pid': process.pid, 'path': str(target), 'argv': ['/bin/sh', str(target)]}))
    raise SystemExit(0)
runpy.run_path('/opt/shared-launch-session.py', run_name='__main__')
