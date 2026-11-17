"""Authenticate through genuine libpq password files before any owning calls."""
from pathlib import Path
import base64
import hashlib
import json
import os
import pwd
import subprocess
import tempfile

fixtures = Path('/opt/pgpass-fixtures')
catalogue = json.loads((fixtures / 'catalogue.json').read_text())
query = "SELECT json_build_object('user',current_user,'database',current_database(),'port',inet_server_port(),'address',inet_server_addr(),'superuser',(SELECT rolsuper FROM pg_roles WHERE rolname=current_user),'version',current_setting('server_version'))::text"
controls = []
baseline = {name: {'sha256': hashlib.sha256((fixtures / name).read_bytes()).hexdigest(),
                   'base64': base64.b64encode((fixtures / name).read_bytes()).decode()}
            for name in catalogue}

for actor in ['root', 'labuser']:
    account = pwd.getpwnam(actor)
    privileges = {'user': account.pw_uid, 'group': account.pw_gid, 'extra_groups': []}
    for name, case in catalogue.items():
        with tempfile.TemporaryDirectory(prefix='native-pgpass-') as directory:
            os.chown(directory, account.pw_uid, account.pw_gid)
            path = Path(directory) / '.pgpass'
            path.write_bytes((fixtures / name).read_bytes())
            os.chown(path, account.pw_uid, account.pw_gid)
            path.chmod(0o600)
            env = {key: value for key, value in os.environ.items() if not key.startswith('PG')}
            env.update(PGPASSFILE=str(path), PGCONNECT_TIMEOUT='3')
            args = ['psql', '-X', '--no-password', '--host', 'localhost', '--port', '5432',
                    '--username', case['user'], '--dbname', case['database'], '-At', '-c', query]
            result = subprocess.run(args, env=env, capture_output=True, text=True, timeout=10, **privileges)
            assert result.returncode == 0, (actor, name, result.stderr)
            data = json.loads(result.stdout)
            assert data['user'] == case['user'] and data['database'] == case['database']
            assert data['port'] == 5432 and data['address'] is not None and data['superuser'] is False
            assert data['version'].startswith('16.15 ')
            controls.append({'actor': actor, 'uid': account.pw_uid, 'case': name, 'argv': args,
                             'exit': result.returncode, 'reply': data, 'stderr': result.stderr})
        assert not Path(directory).exists()

    for kind in ['wrong', 'permissions', 'missing']:
        with tempfile.TemporaryDirectory(prefix='native-pgpass-denial-') as directory:
            os.chown(directory, account.pw_uid, account.pw_gid)
            path = Path(directory) / '.pgpass'
            if kind != 'missing':
                raw = (fixtures / 'plain.pgpass').read_bytes()
                if kind == 'wrong':
                    raw = raw.replace(b'pgpass-lab-password', b'module-target-wrong-password')
                path.write_bytes(raw)
                os.chown(path, account.pw_uid, account.pw_gid)
                path.chmod(0o644 if kind == 'permissions' else 0o600)
            env = {key: value for key, value in os.environ.items() if not key.startswith('PG')}
            env.update(PGPASSFILE=str(path), PGCONNECT_TIMEOUT='3')
            args = ['psql', '-X', '--no-password', '--host', 'localhost', '--port', '5432',
                    '--username', 'pgpass_user', '--dbname', 'pgpass_lab', '-At', '-c', query]
            result = subprocess.run(args, env=env, capture_output=True, text=True, timeout=10, **privileges)
            assert result.returncode == 2 and not result.stdout.strip(), (actor, kind, result.returncode, result.stdout, result.stderr)
            assert 'password' in result.stderr.lower()
            if kind == 'permissions':
                assert 'group or world access' in result.stderr
            controls.append({'actor': actor, 'uid': account.pw_uid, 'case': kind,
                             'argv': args, 'exit': result.returncode, 'stderr': result.stderr})
        assert not Path(directory).exists()

admin_env = dict(os.environ, PGPASSWORD='module-target-pg-admin-password', PGCONNECT_TIMEOUT='3')
admin = subprocess.run(['psql', '-X', '--no-password', '-h', '127.0.0.1', '-U', 'postgres', '-d', 'postgres', '-At', '-c',
                        "SELECT json_agg(json_build_object('type',type,'method',auth_method,'error',error)) FROM pg_hba_file_rules"],
                       env=admin_env, capture_output=True, text=True, timeout=10)
assert admin.returncode == 0, admin.stderr
hba = json.loads(admin.stdout)
assert hba and all(row['method'] == 'scram-sha-256' and row['error'] is None for row in hba)
resources = {name: dict(line.split() for line in Path('/sys/fs/cgroup', name).read_text().splitlines())
             for name in ['memory.events', 'pids.events']}
assert resources['memory.events']['oom'] == resources['memory.events']['oom_kill'] == '0'
assert resources['pids.events']['max'] == '0'
after = {name: hashlib.sha256((fixtures / name).read_bytes()).hexdigest() for name in catalogue}
assert after == {name: value['sha256'] for name, value in baseline.items()}
packages = subprocess.check_output(['dpkg-query', '-W', '-f=${Package}=${Version}\n', 'python3', 'postgresql-16', 'postgresql-client-16', 'libpq5'], text=True)
assert dict(line.split('=', 1) for line in packages.splitlines()) == {
    'python3': '3.13.5-1', 'postgresql-16': '16.15-1.pgdg13+2',
    'postgresql-client-16': '16.15-1.pgdg13+2', 'libpq5': '18.6-1.pgdg13+2',
}
print(json.dumps({'hostname': subprocess.check_output(['hostname'], text=True).strip(), 'uid': os.geteuid(),
                  'os_release': Path('/etc/os-release').read_text(),
                  'packages': packages,
                  'client_version': subprocess.check_output(['psql', '--version'], text=True),
                  'catalogue': catalogue, 'fixtures': baseline, 'controls': controls, 'hba': hba,
                  'resources': resources, 'native_passed': True, 'owner_calls': 0}, indent=2))
