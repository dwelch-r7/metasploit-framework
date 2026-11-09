"""Capture actual OS identity, files and command evidence outside Framework."""
import base64
import json
from pathlib import Path
import subprocess

configs = {}
for filename in ('/etc/shells', '/etc/ca-certificates.conf', '/etc/security/access.conf'):
    path = Path(filename)
    assert path.is_file(), filename
    configs[filename] = base64.b64encode(path.read_bytes()).decode('ascii')
assert Path('/.dockerenv').is_file()
proof = subprocess.run(['/opt/module-target-tools/lab-command'], check=True, capture_output=True, text=True)
assert proof.stdout == 'module-target-command-proof\n'
print(json.dumps(dict(hostname=subprocess.check_output(['hostname'], text=True).strip(),
                     kernel=subprocess.check_output(['uname', '-r'], text=True).strip(),
                     release=Path('/etc/os-release').read_text(), configs=configs,
                     uid=subprocess.check_output(['id', '-u'], text=True).strip(),
                     container='Docker', command='/opt/module-target-tools/lab-command')))
