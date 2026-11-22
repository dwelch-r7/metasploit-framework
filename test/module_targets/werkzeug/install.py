"""Install genuine, checksum-pinned PyPI artifacts without vendor patches."""
from pathlib import Path
import hashlib
import importlib.metadata
import json
import subprocess
import sys
import tempfile
import urllib.request

here = Path(__file__).parent
pins = json.loads((here / 'packages.json').read_text())
version = sys.argv[1]
assert version in pins and version != 'markupsafe'
with tempfile.TemporaryDirectory(prefix='werkzeug-packages-') as directory:
    artifacts = []
    for selected in ['markupsafe', version]:
        pin = pins[selected]
        with urllib.request.urlopen(pin['url'], timeout=30) as response:
            data = response.read()
        assert hashlib.sha256(data).hexdigest() == pin['sha256']
        artifact = Path(directory, pin['filename'])
        artifact.write_bytes(data)
        subprocess.run([sys.executable, '-m', 'pip', 'install', '--disable-pip-version-check',
                        '--no-cache-dir', '--no-deps', '--no-build-isolation', str(artifact)], check=True)
        assert importlib.metadata.version(pin['package']) == pin['version']
        artifacts.append(pin)
import werkzeug
origin = Path(werkzeug.__file__).parent
files = {str(path.relative_to(origin)): hashlib.sha256(path.read_bytes()).hexdigest()
         for path in sorted(origin.rglob('*.py'))}
(here / 'installed.json').write_text(json.dumps(dict(python=sys.version, artifacts=artifacts,
                                                   werkzeug_root=str(origin), source_sha256=files), indent=2) + '\n')
