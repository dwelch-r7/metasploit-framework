"""Remove only hash-checked session artifacts owned by the recorded actor."""
from pathlib import Path
import hashlib
import json
import re
import sys

user_uid, name, payload_sha, proof_path, proof_sha = sys.argv[1:]
user_uid = int(user_uid)
assert user_uid in [0, 1001]
assert name in ['shell-session.sh', 'meterpreter-session.elf']
source = Path('/opt/module-target-artifacts', name)
target = Path('/tmp', name)
for path in [source, target]:
    assert path.is_file() and hashlib.sha256(path.read_bytes()).hexdigest() == payload_sha
assert target.stat().st_uid == user_uid
assert proof_path == '/tmp/module-target-session-proof' or re.fullmatch(r'/tmp/module-target-druid-session-[0-9_]+-[0-9]+', proof_path)
assert not Path('/tmp/module-target-session-proof').exists()
assert re.fullmatch(r'/tmp/module-target-druid-session-[0-9_]+-[0-9]+', proof_path)
markers = {Path(proof_path): proof_sha}
for path, digest in markers.items():
    assert path.is_file() and path.stat().st_uid == user_uid
    assert hashlib.sha256(path.read_bytes()).hexdigest() == digest
for path in markers:
    path.unlink()
target.unlink()
print(json.dumps({'actor_uid': user_uid, 'target_payload_absent': not target.exists(),
                  'markers_absent': all(not path.exists() for path in markers),
                  'source_artifact_retained': True, 'source_sha256': payload_sha}))
