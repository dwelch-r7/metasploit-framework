"""Launch only a task-owned real ELF as the genuine NiFi service UID."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

assert os.getuid() == 1000 and os.getgid() == 1000, (os.getuid(), os.getgid())
source = Path(sys.argv[1]).resolve(strict=True)
assert source.parent == Path('/opt/module-target-artifacts'), source
assert source.name in ('shell-session.elf', 'meterpreter-session.elf'), source
assert source.read_bytes().startswith(b'\x7fELF'), source
target = Path('/tmp') / source.name
shutil.copyfile(source, target)
target.chmod(0o700)
with open('/tmp/module-target-nifi-session.log', 'ab', buffering=0) as log:
    process = subprocess.Popen([str(target)], stdin=subprocess.DEVNULL,
                               stdout=log, stderr=subprocess.STDOUT,
                               start_new_session=True)
print(json.dumps({'pid': process.pid, 'path': str(target), 'uid': os.getuid(), 'gid': os.getgid()}))
