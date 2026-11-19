"""Read stock target state without installing a runtime inside Kafka UI."""
import json
import re
import sys

import native as target


def process(identifier):
    pid = int(identifier)
    target.check('inspection-process-id', pid > 1)
    script = 'if [ ! -r "/proc/$1/status" ]; then printf "ABSENT\\n"; exit; fi; cat "/proc/$1/status"; printf "\\nNATIVE_EXE\\n"; readlink "/proc/$1/exe"; sha256sum "/proc/$1/exe"'
    output = target.command('app', 'sh', '-c', script, 'native-process', str(pid), required=False).decode()
    if output == 'ABSENT\n':
        return {'exists': False, 'pid': pid}
    status, separator, executable = output.partition('\nNATIVE_EXE\n')
    uid = re.search(r'^Uid:\s+(\d+)', status, re.M)
    parent = re.search(r'^PPid:\s+(\d+)', status, re.M)
    lines = executable.splitlines()
    return {'exists': True, 'pid': pid, 'uid': int(uid[1]) if uid else None, 'parent': int(parent[1]) if parent else None, 'exe': lines[0] if lines else None, 'exe_sha256': lines[1].split()[0] if len(lines) > 1 else None, 'complete': bool(separator and uid and parent and len(lines) > 1)}


def connections(port_text):
    port = int(port_text)
    target.check('inspection-port', 0 < port < 65536)
    output = target.command('app', 'sh', '-c', 'cat /proc/net/tcp; if [ -r /proc/net/tcp6 ]; then cat /proc/net/tcp6; fi').decode()
    rows = []
    for line in output.splitlines():
        fields = line.split()
        if len(fields) > 9 and re.fullmatch(r'[0-9A-F]+:[0-9A-F]{4}', fields[2]) and int(fields[2].split(':')[1], 16) == port:
            rows.append({'state': fields[3], 'uid': int(fields[7]), 'inode': fields[9]})
    return rows


try:
    result = {'file': lambda: target.file_state(sys.argv[4]), 'process': lambda: process(sys.argv[4]), 'connections': lambda: connections(sys.argv[4])}[sys.argv[3]]()
    target.record.update(passed=True, data=result)
except Exception as error:
    target.record.update(passed=False, error={'type': type(error).__name__, 'message': str(error)})
finally:
    print(json.dumps(target.record))
if not target.record.get('passed'):
    raise SystemExit(1)
