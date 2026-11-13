"""Observe process birth identities and non-listening connections without mutation."""
from pathlib import Path
import json
import os
import re


def processes():
    rows = []
    for path in Path('/proc').glob('[0-9]*'):
        try:
            status = (path / 'status').read_text()
            if int(re.search(r'^Uid:\s+(\d+)', status, re.M).group(1)) != os.getuid() or int(path.name) == os.getpid():
                continue
            command = (path / 'cmdline').read_bytes().replace(b'\0', b' ').decode(errors='replace')
            if '/opt/libssh-lab/health.py' in command:
                continue
            fields = (path / 'stat').read_text().split(') ', 1)[1].split()
            rows.append({'pid': int(path.name), 'starttime': fields[19], 'state': fields[0], 'ppid': int(fields[1]), 'cmdline': command})
        except (FileNotFoundError, ProcessLookupError, PermissionError):
            continue
    return rows


def snapshot():
    connections = []
    for family in ['tcp', 'tcp6']:
        for line in (Path('/proc/net') / family).read_text().splitlines()[1:]:
            fields = line.split()
            if fields[3] not in ['0A', '06'] and int(fields[1].split(':')[1], 16) in range(2222, 2229):
                connections.append({'family': family, 'local': fields[1], 'remote': fields[2], 'state': fields[3], 'inode': fields[9]})
    return {'processes': processes(), 'connections': connections}


if __name__ == '__main__':
    print(json.dumps(snapshot(), sort_keys=True))
