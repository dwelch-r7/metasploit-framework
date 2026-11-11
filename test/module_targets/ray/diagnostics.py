"""Bounded native Ray log tails and resource counters before teardown."""
import base64, hashlib, json
from pathlib import Path
import psutil
directory = Path('/tmp/ray/session_latest/logs').resolve()
files = sorted(path for path in directory.rglob('*') if path.is_file())
assert len(files) <= 200, len(files)
records = []
for path in files:
    raw = path.read_bytes()
    records.append({'path': str(path.relative_to(directory)), 'size': len(raw),
                    'sha256': hashlib.sha256(raw).hexdigest(),
                    'tail_base64': base64.b64encode(raw[-65536:]).decode()})
cgroups = {}
for name in ['pids.current', 'pids.peak', 'pids.events', 'memory.events', 'memory.peak']:
    path = Path('/sys/fs/cgroup') / name
    cgroups[name] = path.read_text() if path.exists() else None
processes = []
for process in psutil.process_iter(['pid', 'name', 'num_threads', 'status', 'memory_info']):
    row = process.info
    row['rss'] = row.pop('memory_info').rss
    processes.append(row)
print(json.dumps({'directory': str(directory), 'logs': records,
                  'cgroups': cgroups, 'processes': processes}))
