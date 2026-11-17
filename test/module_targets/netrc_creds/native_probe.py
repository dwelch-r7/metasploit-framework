"""Run the captured client controls and observe actual post-module target state."""
from contextlib import redirect_stdout
from pathlib import Path
import hashlib
import io
import json
import runpy

captured = io.StringIO()
with redirect_stdout(captured):
    runpy.run_path('/opt/netrc-fixture-native.py')
data = json.loads(captured.getvalue())
files = {}
for name in ['/etc/passwd', '/etc/group', '/root/.netrc', '/home/labuser/.netrc']:
    path = Path(name)
    if not path.exists():
        files[name] = {'exists': False}
        continue
    raw = path.read_bytes()
    info = path.stat()
    files[name] = {'exists': True, 'sha256': hashlib.sha256(raw).hexdigest(),
                   'uid': info.st_uid, 'gid': info.st_gid, 'mode': oct(info.st_mode & 0o777)}
data['files'] = files
print(json.dumps(data, indent=2))
