"""Cache exact vendor wheels used for independent installed-source verification."""
from pathlib import Path
import hashlib
import json
import urllib.request

root = Path.cwd()
config = json.loads((Path(__file__).parent / 'profiles.json').read_text())
cache = root / config['cache_dir']
cache.mkdir(parents=True, exist_ok=True)
for release, row in config['releases'].items():
    path = cache / row['filename']
    if not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest() != row['sha256']:
        with urllib.request.urlopen(row['url'], timeout=60) as response:
            raw = response.read()
        if hashlib.sha256(raw).hexdigest() != row['sha256']:
            raise ValueError('Vendor wheel checksum mismatch: ' + release)
        temporary = path.with_suffix('.download')
        temporary.write_bytes(raw)
        temporary.replace(path)
    print('Verified BentoML ' + release)
