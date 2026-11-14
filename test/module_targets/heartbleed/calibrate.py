"""Run all independent clients before/after owning module executions."""
from pathlib import Path
import json
import subprocess
import sys

root = Path(__file__).resolve().parent
record = {'status': 'running', 'controls': {}}
for name in ['native_probe.py', 'conditioned_probe.py', 'starttls_probe.py', 'ec_probe.py']:
    outcome = subprocess.run([sys.executable, '-W', 'ignore::DeprecationWarning', str(root / name), *sys.argv[1:]], capture_output=True, text=True, check=True)
    data = json.loads(outcome.stdout)
    assert data['status'] == 'passed'
    record['controls'][name] = data
record['certificates'] = {name: (Path('/tmp/heartbleed-lab') / name).read_text() for name in ['cert.pem', 'ec-cert.pem']}
record['status'] = 'passed'
print(json.dumps(record))
