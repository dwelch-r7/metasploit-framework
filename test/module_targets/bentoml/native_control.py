"""Run owner-independent vendor controls in the target, preserving full replies."""
from pathlib import Path
import hashlib
import json
import subprocess
import sys
import zipfile

runtime = json.loads(Path(sys.argv[1]).read_text())
out = Path(runtime['directory'])
here = Path(__file__).parent
config = json.loads((here / 'profiles.json').read_text())
row = config['releases'][runtime['release']]
wheel = Path.cwd() / config['cache_dir'] / row['filename']
if hashlib.sha256(wheel.read_bytes()).hexdigest() != row['sha256']:
    raise ValueError('Vendor wheel checksum mismatch')
with zipfile.ZipFile(wheel) as archive:
    runtime['vendor_files'] = {name: hashlib.sha256(archive.read(name)).hexdigest() for name in archive.namelist() if name.endswith('.py') and name.startswith(('bentoml/', '_bentoml_impl/', '_bentoml_sdk/', 'bentoml_cli/'))}
runtime.update(uid=config['uid'], port=config['port'])
source = 'runtime = ' + repr(runtime) + '\n' + (here / 'native_protocol.py').read_text()
process = subprocess.run(runtime['compose'] + ['exec', '-T', 'app', 'python3', '-'], input=source, capture_output=True, text=True, timeout=120)
(out / 'native.stdout').write_text(process.stdout)
(out / 'native.stderr').write_text(process.stderr)
line = next((line for line in process.stdout.splitlines() if line.startswith('BENTOML_NATIVE_JSON=')), None)
if not line:
    raise RuntimeError('Native client did not produce its evidence: ' + process.stderr[-1200:])
report = json.loads(line.split('=', 1)[1])
(out / 'native-proof.json').write_text(json.dumps(report, indent=2) + '\n')
print(json.dumps({'exit': process.returncode, 'native_passed': report.get('native_passed', False), 'failure': report.get('failure')}))
sys.exit(0 if process.returncode == 0 and report.get('native_passed') else 1)
