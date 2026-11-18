"""Cache the small vendor-documented password wrapper without host installation."""
from pathlib import Path
import hashlib
import json
import urllib.request

config = json.loads((Path(__file__).parent / 'profiles.json').read_text())
package = config['password_package']
cache = Path.cwd() / config['cache_dir']
cache.mkdir(parents=True, exist_ok=True)
path = cache / package['filename']
if not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest() != package['sha256']:
    with urllib.request.urlopen(package['url'], timeout=45) as response:
        raw = response.read()
    if len(raw) != package['bytes'] or hashlib.sha256(raw).hexdigest() != package['sha256']:
        raise ValueError('Flask-Bcrypt vendor archive checksum differs')
    temporary = path.with_suffix('.download')
    temporary.write_bytes(raw)
    temporary.replace(path)
print('Verified Flask-Bcrypt ' + package['version'] + '; no host package installed')
