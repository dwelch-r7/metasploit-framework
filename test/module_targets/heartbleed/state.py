"""Observe stable service processes and connections without modifying them."""
from pathlib import Path
import json
import os
import subprocess

root = Path('/tmp/heartbleed-lab')
processes = {}
for name, pid in json.loads((root / 'service-processes.json').read_text()).items():
    os.kill(pid, 0)
    fields = Path('/proc', str(pid), 'stat').read_text().rsplit(') ', 1)[1].split()
    processes[name] = {'pid': pid, 'starttime': fields[19], 'command': Path('/proc', str(pid), 'cmdline').read_bytes().replace(b'\0', b' ').decode()}
connections = subprocess.check_output(['ss', '-Htn', 'state', 'established'], text=True).splitlines()
print(json.dumps({'processes': processes, 'connections': connections}))
