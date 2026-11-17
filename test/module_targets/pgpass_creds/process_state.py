"""Prove and, if needed, stop only the recorded task-owned session process."""
from pathlib import Path
import hashlib
import json
import os
import signal
import sys
import time

def identity(pid):
    assert isinstance(pid, int) and pid > 1
    path = Path('/proc', str(pid))
    if not path.exists():
        return {'pid': pid, 'alive': False}
    try:
        fields = (path / 'stat').read_text().rsplit(')', 1)[1].split()
        uid = next(int(line.split()[1]) for line in (path / 'status').read_text().splitlines() if line.startswith('Uid:'))
    except FileNotFoundError:
        if not path.exists():
            return {'pid': pid, 'alive': False}
        raise
    try:
        executable = os.readlink(path / 'exe')
        digest = hashlib.sha256((path / 'exe').read_bytes()).hexdigest()
    except (PermissionError, FileNotFoundError):
        executable = digest = None
    return {'pid': pid, 'alive': True, 'uid': uid, 'starttime': int(fields[19]),
            'state': fields[0], 'executable': executable, 'exe_sha256': digest}

action = sys.argv[1]
if action == 'identity':
    print(json.dumps(identity(int(sys.argv[2]))))
    raise SystemExit(0)
if action == 'stop':
    expected = json.loads(sys.argv[2])
    pid = expected['pid']
    signals = []
    for signum in [None, signal.SIGTERM, signal.SIGKILL]:
        current = identity(pid)
        if not current['alive']:
            break
        for key in ['uid', 'starttime']:
            assert current[key] == expected[key], (key, current, expected)
        if expected.get('exe_sha256') and current['state'] != 'Z':
            assert current['exe_sha256'] == expected['exe_sha256']
        if signum:
            os.kill(pid, signum)
            signals.append(signum)
        deadline = time.monotonic() + 3
        while identity(pid)['alive'] and time.monotonic() < deadline:
            time.sleep(0.05)
    assert not identity(pid)['alive']
    print(json.dumps({'pid': pid, 'absent': True, 'operator_signals': signals}))
    raise SystemExit(0)
if action == 'artifacts':
    name, sha, marker, marker_sha = sys.argv[2:]
    assert name in ['shell-session.elf', 'meterpreter-session.elf']
    source = Path('/opt/module-target-artifacts', name)
    target = Path('/tmp', name)
    assert all(path.is_file() and hashlib.sha256(path.read_bytes()).hexdigest() == sha for path in [source, target])
    target.unlink()
    markers = {Path('/tmp/module-target-session-proof'): hashlib.sha256(b'').hexdigest()}
    if Path(marker) in markers:
        assert markers[Path(marker)] == marker_sha
    markers[Path(marker)] = marker_sha
    for path, digest in markers.items():
        assert path.parent == Path('/tmp') and path.is_file() and path.stat().st_uid == 0
        assert hashlib.sha256(path.read_bytes()).hexdigest() == digest
        path.unlink()
    print(json.dumps({'target_payload_absent': not target.exists(), 'markers_absent': True,
                      'source_artifact_retained': True, 'source_sha256': sha}))
    raise SystemExit(0)
raise ValueError(action)
