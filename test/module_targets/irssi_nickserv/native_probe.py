"""Run genuine service controls and retain selected owning home state."""
from contextlib import redirect_stdout
from pathlib import Path
import hashlib
import io
import json
import os
import runpy
import sys

phase = sys.argv[1]
assert phase in ['before', 'after']
sys.argv = ['/opt/irssi-fixture-native.py', 'probe']
with redirect_stdout(io.StringIO()):
    runpy.run_path('/opt/irssi-fixture-native.py', run_name='__main__')
data = json.loads(Path('/opt/native-artifacts/nickserv-probe.json').read_text())
data.update(phase=phase, hostname=os.uname().nodename, uid=os.geteuid())
data['files'] = dict(data['after']['files'])
data['services'] = data['after']['services']
fixtures = Path('/opt/irssi-fixtures')
data['fixtures'] = {path.name: hashlib.sha256(path.read_bytes()).hexdigest() for path in sorted(fixtures.iterdir()) if path.is_file()}
for home in ['/root', '/home/labuser', '/home/otheruser']:
    directory = Path(home, '.irssi')
    path = directory / 'config'
    data['files'][str(directory)] = {'exists': directory.exists()}
    data['files'][str(path)] = {'exists': path.exists()}
    if path.exists():
        data['files'][str(path)].update(sha256=hashlib.sha256(path.read_bytes()).hexdigest(), uid=path.stat().st_uid, mode=oct(path.stat().st_mode & 0o777))
print(json.dumps(data, indent=2))
