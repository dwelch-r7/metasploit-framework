"""Record only descendants of the actual task-owned session PID."""
from pathlib import Path
import json
import sys

parent = int(sys.argv[1])
assert parent > 1
processes = {}
for path in Path('/proc').iterdir():
    if not path.name.isdecimal():
        continue
    try:
        fields = (path / 'stat').read_text().rsplit(')', 1)[1].split()
        status = (path / 'status').read_text().splitlines()
        uid = next(int(line.split()[1]) for line in status if line.startswith('Uid:'))
        processes[int(path.name)] = {'pid': int(path.name), 'ppid': int(fields[1]), 'uid': uid,
                                      'state': fields[0], 'starttime': int(fields[19]), 'alive': True}
    except FileNotFoundError:
        continue
descendants = []
pending = [(parent, 0)]
while pending:
    ancestor, depth = pending.pop(0)
    children = [row for row in processes.values() if row['ppid'] == ancestor]
    for row in children:
        row['depth'] = depth + 1
        descendants.append(row)
        pending.append((row['pid'], depth + 1))
print(json.dumps({'parent': parent, 'descendants': descendants}))
