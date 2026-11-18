"""Retain real Fetchmail controls and the owning home-file baseline."""
from contextlib import redirect_stdout
from pathlib import Path
import hashlib
import io
import json
import os
import runpy
import sys

with redirect_stdout(io.StringIO()):
    runpy.run_path('/opt/fetchmail-fixture-native.py')
data = json.loads(Path('/opt/native-artifacts', 'native-' + sys.argv[1] + '.json').read_text())
data['hostname'] = os.uname().nodename
data['uid'] = os.geteuid()
for name in ['/root/.fetchmailrc', '/home/labuser/.fetchmailrc', '/home/otheruser/.fetchmailrc']:
    path = Path(name)
    data['files'][name] = {'exists': path.exists()}
    if path.exists():
        data['files'][name].update(sha256=hashlib.sha256(path.read_bytes()).hexdigest(), uid=path.stat().st_uid, mode=oct(path.stat().st_mode & 0o777))
print(json.dumps(data, indent=2))
