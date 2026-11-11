"""Bounded read-only log archive capture after a target process exits."""
import base64
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tarfile
import threading

identifier, output = sys.argv[1:]
process = subprocess.Popen(['docker', 'cp', '-L', identifier + ':/tmp/ray/session_latest/logs', '-'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
timer = threading.Timer(25, process.kill)
timer.start()
records = []
result = {'container': identifier, 'scope': 'Exited target log archive; no cgroup counters available', 'complete': False, 'logs': records}
try:
    total = 0
    with tarfile.open(fileobj=process.stdout, mode='r|*') as archive:
        for member in archive:
            if not member.isfile():
                continue
            if len(records) >= 512 or member.size > 8 * 1024 * 1024 or total + member.size > 32 * 1024 * 1024:
                raise ValueError('Log archive exceeds bounded capture budget')
            source = archive.extractfile(member)
            digest = hashlib.sha256()
            tail = b''
            observed = 0
            while True:
                chunk = source.read(65536)
                if not chunk:
                    break
                digest.update(chunk)
                observed += len(chunk)
                tail = (tail + chunk)[-65536:]
            assert observed == member.size
            total += observed
            records.append({'path': member.name, 'size': observed, 'sha256': digest.hexdigest(), 'tail_base64': base64.b64encode(tail).decode()})
    status = process.wait(timeout=5)
    assert status == 0, status
    result['complete'] = True
except (OSError, ValueError, AssertionError, tarfile.TarError, subprocess.SubprocessError) as error:
    result['error'] = {'class': type(error).__name__, 'message': str(error)}
finally:
    timer.cancel()
    if process.poll() is None:
        process.kill()
    _, stderr = process.communicate(timeout=5)
    result['exitstatus'] = process.returncode
    result['stderr'] = stderr.decode(errors='replace')
    Path(output).write_text(json.dumps(result, indent=2) + '\n')
print(json.dumps({'complete': result['complete'], 'logs': len(records), 'error': result.get('error')}))
raise SystemExit(0 if result['complete'] else 1)
