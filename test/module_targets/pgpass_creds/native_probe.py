"""Observe the native libpq controls and selected credential-file state."""
from contextlib import redirect_stdout
from pathlib import Path
import hashlib
import io
import json
import os
import runpy

captured = io.StringIO()
with redirect_stdout(captured):
    runpy.run_path('/opt/pgpass-fixture-native.py')
data = json.loads(captured.getvalue())
data['files'] = {}
for name in ['/etc/passwd', '/etc/group', '/root/.pgpass', '/home/labuser/.pgpass', '/home/otheruser/.pgpass']:
    path = Path(name)
    if not path.exists():
        data['files'][name] = {'exists': False}
    else:
        info = path.stat()
        data['files'][name] = {'exists': True, 'sha256': hashlib.sha256(path.read_bytes()).hexdigest(),
                               'uid': info.st_uid, 'gid': info.st_gid, 'mode': oct(info.st_mode & 0o777)}
pid = int((Path(os.environ['PGDATA']) / 'postmaster.pid').read_text().splitlines()[0])
data['server'] = {'pid': pid, 'command': Path('/proc', str(pid), 'cmdline').read_bytes().replace(b'\0', b' ').decode()}
print(json.dumps(data, indent=2))
