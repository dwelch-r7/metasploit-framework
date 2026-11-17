"""Install only an exact native fixture, authenticate, and recover its home file."""
from pathlib import Path
import base64
import hashlib
import json
import os
import subprocess
import sys

action, fixture = sys.argv[1:]
catalogue = json.loads(Path('/opt/pgpass-fixtures/catalogue.json').read_text())
assert fixture in catalogue and Path(fixture).name == fixture
source = Path('/opt/pgpass-fixtures', fixture).read_bytes()
path = Path('/root/.pgpass')
sha = hashlib.sha256(source).hexdigest()
if action == 'restore':
    present = path.exists()
    if present:
        assert path.is_file() and path.read_bytes() == source
        path.unlink()
    assert not path.exists()
    print(json.dumps({'path': str(path), 'sha256': sha, 'was_present': present, 'absent': True}))
    raise SystemExit(0)

assert action == 'install' and not path.exists()
path.write_bytes(source)
os.chown(path, 0, 0)
path.chmod(0o600)
case = catalogue[fixture]
env = {key: value for key, value in os.environ.items() if not key.startswith('PG')}
env.update(PGPASSFILE=str(path), PGCONNECT_TIMEOUT='3')
query = "SELECT json_build_object('user',current_user,'database',current_database(),'port',inet_server_port(),'superuser',(SELECT rolsuper FROM pg_roles WHERE rolname=current_user))::text"
args = ['psql', '-X', '--no-password', '-h', 'localhost', '-p', '5432', '-U', case['user'], '-d', case['database'], '-At', '-c', query]
result = subprocess.run(args, env=env, capture_output=True, text=True, timeout=10)
assert result.returncode == 0, result.stderr
reply = json.loads(result.stdout)
assert reply == {'user': case['user'], 'database': case['database'], 'port': 5432, 'superuser': False}
print(json.dumps({'path': str(path), 'fixture': fixture, 'sha256': sha, 'base64': base64.b64encode(source).decode(),
                  'uid': path.stat().st_uid, 'mode': oct(path.stat().st_mode & 0o777), 'expected': case,
                  'native_client': {'argv': args, 'exit': result.returncode, 'reply': reply, 'stderr': result.stderr},
                  'native_passed': True}))
