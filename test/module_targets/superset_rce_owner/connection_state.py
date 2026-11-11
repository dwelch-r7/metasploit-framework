"""Read-only target socket ownership for a genuine Python reverse session."""
import json
import os
from pathlib import Path
import socket
import struct
import sys

address, port = sys.argv[1], int(sys.argv[2])
connections = []
for line in Path('/proc/net/tcp').read_text().splitlines()[1:]:
    fields = line.split()
    host_hex, port_hex = fields[2].split(':')
    remote = socket.inet_ntoa(struct.pack('<I', int(host_hex, 16)))
    inode = fields[9]
    if remote == address and int(port_hex, 16) == port and inode != '0':
        owners = []
        for process in Path('/proc').iterdir():
            if not process.name.isdigit():
                continue
            try:
                if any(os.readlink(fd) == 'socket:[' + inode + ']' for fd in (process / 'fd').iterdir()):
                    owners.append({'pid': int(process.name), 'uid': process.stat().st_uid,
                                   'command_base64': __import__('base64').b64encode((process / 'cmdline').read_bytes()).decode()})
            except (FileNotFoundError, PermissionError, ProcessLookupError):
                continue
        connections.append({'inode': inode, 'state': fields[3], 'owners': owners})
print(json.dumps(connections))
