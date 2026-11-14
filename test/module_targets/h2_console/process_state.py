"""Native PID birth, command, UID and callback-socket observations."""
from pathlib import Path
import json
import os

processes = []
for path in Path('/proc').iterdir():
    if not path.name.isdecimal() or int(path.name) == os.getpid():
        continue
    try:
        raw = (path / 'stat').read_text().split(') ', 1)[1].split()
        command = (path / 'cmdline').read_bytes().replace(b'\x00', b' ').decode().strip()
        uid = (path / 'status').read_text().split('Uid:', 1)[1].split()[0]
        processes.append(dict(pid=int(path.name), ppid=int(raw[1]), state=raw[0], birth=raw[19], uid=uid, command=command))
    except FileNotFoundError:
        continue
connections = []
for name in ('tcp', 'tcp6'):
    for line in (Path('/proc/net') / name).read_text().splitlines()[1:]:
        fields = line.split()
        if int(fields[2].rsplit(':', 1)[1], 16) == 4492 and fields[3] != '06':
            connections.append(dict(local=fields[1], remote=fields[2], state=fields[3]))
print(json.dumps(dict(processes=processes, connections=connections)))
