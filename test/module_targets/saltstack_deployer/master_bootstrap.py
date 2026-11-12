"""Start exact public handler ELF bytes as administrative fixture setup."""
import base64
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys

configuration = json.loads(sys.argv[1])
path = configuration['path']
assert re.fullmatch(r'/tmp/module-target-master-bootstrap-[a-f0-9]+', path)
raw = base64.b64decode(configuration['executable_base64'])
assert raw.startswith(b'\x7fELF')
assert hashlib.sha256(raw).hexdigest() == configuration['executable_sha256']
destination = Path(path)
destination.write_bytes(raw)
destination.chmod(0o700)
process = subprocess.Popen([path], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL, start_new_session=True)
print('SALT_DEPLOY_BOOTSTRAP=' + json.dumps({'path': path, 'launcher_pid': process.pid,
      'executable_sha256': hashlib.sha256(destination.read_bytes()).hexdigest(),
      'bytes': destination.stat().st_size, 'mode': oct(destination.stat().st_mode & 511)}))
