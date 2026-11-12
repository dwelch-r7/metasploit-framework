"""Install the checksum-pinned Debian network utility used by genuine Salt."""
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
import urllib.request

package = json.loads(Path('/opt/module-target/system-package.json').read_text())
raw = urllib.request.urlopen(package['url'], timeout=120).read()
assert len(raw) == int(package['Size'])
assert hashlib.sha256(raw).hexdigest() == package['SHA256']
with tempfile.NamedTemporaryFile(suffix='.deb') as archive:
    archive.write(raw)
    archive.flush()
    subprocess.run(['dpkg', '--install', archive.name], check=True)
