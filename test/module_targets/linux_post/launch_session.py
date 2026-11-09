"""Run a task-owned generated payload; never invokes a network exploitation stub."""
import json
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
argv = [str(target)]
with open('/tmp/module-target-session.log', 'ab', buffering=0) as log:
    process = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=log,
                               stderr=subprocess.STDOUT, start_new_session=True)
print(json.dumps(dict(pid=process.pid, path=str(target), argv=argv)))
