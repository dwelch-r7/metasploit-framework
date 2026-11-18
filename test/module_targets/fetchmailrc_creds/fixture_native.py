from pathlib import Path
import base64
import hashlib
import json
import os
import pwd
import subprocess
import sys
import tempfile
import time

phase = sys.argv[1]
assert phase in ['before', 'after']
fixtures = Path('/opt/fetchmail-fixtures')
catalogue = json.loads((fixtures / 'catalogue.json').read_text())
artifact = Path('/opt/native-artifacts', 'native-' + phase + '.json')
log = Path('/tmp/dovecot-module-target.log')
data = {'phase': phase, 'native_passed': False, 'controls': [], 'owner_calls': 0,
        'fixtures': {name: {'sha256': hashlib.sha256((fixtures / name).read_bytes()).hexdigest(),
                            'base64': base64.b64encode((fixtures / name).read_bytes()).decode()}
                     for name in catalogue}}

def save():
    artifact.write_text(json.dumps(data, indent=2) + '\n')

def messages():
    return sorted(hashlib.sha256(p.read_bytes()).hexdigest()
                  for area in ['new', 'cur'] for p in Path('/srv/mail/Maildir', area).iterdir() if p.is_file())

def control(actor, name, raw, accounts, expected_exit, mode=0o600):
    account = pwd.getpwnam(actor)
    with tempfile.TemporaryDirectory(prefix='native-fetchmail-') as directory:
        os.chown(directory, account.pw_uid, account.pw_gid)
        path = Path(directory, '.fetchmailrc')
        if raw is not None:
            path.write_bytes(raw)
            os.chown(path, account.pw_uid, account.pw_gid)
            path.chmod(mode)
        env = {key: value for key, value in os.environ.items() if not key.startswith('FETCHMAIL')}
        env.update(HOME=directory, FETCHMAILHOME=directory, USER=actor, LOGNAME=actor, LC_ALL='C')
        assert not Path(directory, '.netrc').exists()
        start = log.stat().st_size if log.exists() else 0
        args = ['fetchmail', '--check', '--nodetach', '--nosyslog', '--verbose', '-f', str(path)]
        result = subprocess.run(args, env=env, capture_output=True, text=True, timeout=40,
                                user=account.pw_uid, group=account.pw_gid, extra_groups=[])
        deadline = time.monotonic() + 3
        while True:
            observed = log.read_bytes()[start:].decode(errors='replace') if log.exists() else ''
            if all('Login: user=<' + row['user'] + '>' in observed for row in accounts):
                break
            if time.monotonic() >= deadline:
                break
            time.sleep(0.05)
        row = {'actor': actor, 'uid': account.pw_uid, 'case': name, 'argv': args,
               'file_sha256': hashlib.sha256(raw).hexdigest() if raw is not None else None,
               'mode': oct(mode), 'exit': result.returncode, 'stdout': result.stdout,
               'stderr': result.stderr, 'native_server_log': observed, 'expected_accounts': accounts}
        data['controls'].append(row)
        save()
        if expected_exit is None:
            assert result.returncode != 0, row
        else:
            assert result.returncode == expected_exit, row
        assert all('Login: user=<' + item['user'] + '>' in observed for item in accounts), row
        if expected_exit != 0:
            assert 'Login: user=<' not in observed, row
    assert not Path(directory).exists()

save()
try:
    initial = messages()
    assert len(initial) == 1
    data['message_hashes_before'] = initial
    for actor in ['root', 'labuser']:
        for name, case in catalogue.items():
            raw = (fixtures / name).read_bytes()
            assert hashlib.sha256(raw).hexdigest() == case['sha256']
            control(actor, name, raw, case['accounts'], 0)
        plain = (fixtures / 'plain.fetchmailrc').read_bytes()
        control(actor, 'wrong-password', plain.replace(b'module-target-password', b'module-target-wrong-password'), [], 3)
        control(actor, 'permissions', plain, [], 6, 0o644)
        control(actor, 'missing', None, [], None)
    data['message_hashes_after'] = messages()
    assert data['message_hashes_after'] == initial
    data['packages'] = subprocess.check_output(['dpkg-query', '-W', '-f=${Package}=${Version}\n',
                                               'fetchmail', 'python3', 'dovecot-core', 'dovecot-pop3d', 'dovecot-imapd', 'openssl'], text=True)
    assert dict(line.split('=', 1) for line in data['packages'].splitlines()) == {
        'fetchmail': '6.4.27-1ubuntu0.2', 'python3': '3.10.6-1~22.04.1',
        'dovecot-core': '1:2.3.16+dfsg1-3ubuntu2.9', 'dovecot-pop3d': '1:2.3.16+dfsg1-3ubuntu2.9',
        'dovecot-imapd': '1:2.3.16+dfsg1-3ubuntu2.9', 'openssl': '3.0.2-0ubuntu1.30'}
    data['files'] = {name: hashlib.sha256(Path(name).read_bytes()).hexdigest()
                     for name in ['/etc/passwd', '/etc/group', '/etc/dovecot/users', '/etc/dovecot/dovecot.conf']}
    data['resources'] = {name: dict(line.split() for line in Path('/sys/fs/cgroup', name).read_text().splitlines())
                         for name in ['memory.events', 'pids.events']}
    assert data['resources']['memory.events']['oom'] == data['resources']['memory.events']['oom_kill'] == '0'
    assert data['resources']['pids.events']['max'] == '0'
    data['native_passed'] = True
except BaseException as error:
    data['failure'] = {'type': type(error).__name__, 'message': str(error)}
    raise
finally:
    save()
print(json.dumps({'phase': phase, 'native_passed': data['native_passed'], 'controls': len(data['controls']), 'owner_calls': 0}), flush=True)
