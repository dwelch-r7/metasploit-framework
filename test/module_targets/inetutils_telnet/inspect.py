"""Inspect actual proof files and callback processes without interpreting echoes."""
from pathlib import Path
import base64, hashlib, json, sys


def proof_file(name):
    path = Path(name)
    try:
        content = path.read_bytes()
        return {'exists': True, 'uid': path.stat().st_uid,
                'base64': base64.b64encode(content).decode()}
    except FileNotFoundError:
        return {'exists': False, 'uid': None, 'base64': None}


def process_record(identifier):
    path = Path('/proc') / identifier
    try:
        status = (path / 'status').read_text()
        uid = int(next(line for line in status.splitlines() if line.startswith('Uid:')).split()[1])
        state = next(line for line in status.splitlines() if line.startswith('State:')).split()[1]
        try:
            executable = hashlib.sha256((path / 'exe').read_bytes()).hexdigest()
        except FileNotFoundError:
            executable = None
        return {'exists': True, 'uid': uid, 'state': state, 'exe_sha256': executable}
    except (FileNotFoundError, ProcessLookupError):
        return {'exists': False, 'uid': None, 'state': None, 'exe_sha256': None}


if sys.argv[1] == 'file':
    result = proof_file(sys.argv[2])
elif sys.argv[1] == 'exists':
    result = Path(sys.argv[2]).is_file()
elif sys.argv[1] == 'process':
    result = process_record(sys.argv[2])
else:
    raise ValueError('Unknown inspection operation')
print(json.dumps(result))
