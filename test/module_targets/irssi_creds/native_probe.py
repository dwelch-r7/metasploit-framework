"""Retain real terminal/rawlog controls and selected home-file state."""
from contextlib import redirect_stdout
from pathlib import Path
import hashlib
import io
import json
import os
import runpy
import sys

with redirect_stdout(io.StringIO()):
    runpy.run_path('/opt/irssi-fixture-native.py', run_name='__main__')
data = json.loads(Path('/opt/native-artifacts', 'native-' + sys.argv[1] + '.json').read_text())
data['hostname'] = os.uname().nodename
data['uid'] = os.geteuid()
for home in ['/root', '/home/labuser', '/home/otheruser']:
    directory = Path(home, '.irssi')
    path = directory / 'config'
    data['files'][str(directory)] = {'exists': directory.exists()}
    data['files'][str(path)] = {'exists': path.exists()}
    if path.exists():
        data['files'][str(path)].update(sha256=hashlib.sha256(path.read_bytes()).hexdigest(), uid=path.stat().st_uid, mode=oct(path.stat().st_mode & 0o777))
print(json.dumps(data, indent=2))
