"""Create and cryptographically validate task-owned modern GnuPG keyrings."""
from pathlib import Path
import base64
import hashlib
import json
import os
import pwd
import re
import shutil
import subprocess
import tempfile
import time

OUTPUT = Path('/opt/native-artifacts/probe.json')
data = {'native_passed': False, 'owner_calls': 0, 'controls': []}


def save():
    OUTPUT.write_text(json.dumps(data, indent=2) + '\n')


def agents(home, uid):
    rows = []
    for path in Path('/proc').iterdir():
        if not path.name.isdecimal():
            continue
        try:
            arguments = [value.decode() for value in (path / 'cmdline').read_bytes().split(b'\x00') if value]
            if not arguments or Path(arguments[0]).name != 'gpg-agent' or str(home) not in arguments:
                continue
            fields = (path / 'stat').read_text().rsplit(')', 1)[1].split()
            status = (path / 'status').read_text().splitlines()
            actual_uid = next(int(line.split()[1]) for line in status if line.startswith('Uid:'))
            assert actual_uid == uid
            rows.append({'pid': int(path.name), 'uid': actual_uid, 'starttime': int(fields[19]), 'argv': arguments})
        except FileNotFoundError:
            continue
    return rows


def control(actor, protected, homedir=None, keep=False):
    account = pwd.getpwnam(actor)
    directory = Path(tempfile.mkdtemp(prefix='native-gpg-' + actor + (' space home-' if actor == 'labuser' else '-')))
    os.chown(directory, account.pw_uid, account.pw_gid)
    home = directory / '.gnupg' if homedir is None else Path(homedir)
    if homedir is not None:
        assert home == Path(account.pw_dir) / '.gnupg' and not home.exists()
    home.mkdir(mode=0o700)
    os.chown(home, account.pw_uid, account.pw_gid)
    row = {'actor': actor, 'uid': account.pw_uid, 'actual_account_home': account.pw_dir,
           'protected': protected, 'homedir': str(home), 'commands': []}
    data['controls'].append(row)
    save()
    environment = {'PATH': '/usr/bin:/bin', 'HOME': account.pw_dir, 'USER': actor,
                   'LOGNAME': actor, 'LC_ALL': 'C.UTF-8', 'GNUPGHOME': str(home)}
    phrase = 'module-target-gpg-passphrase' if protected else ''

    def command(label, arguments, password=None, required=True, timeout=60):
        result = subprocess.run(arguments, input=None if password is None else password + '\n',
                                env=environment, user=account.pw_uid, group=account.pw_gid, extra_groups=[],
                                capture_output=True, text=True, timeout=timeout)
        record = {'label': label, 'argv': arguments, 'exit': result.returncode,
                  'stdout': result.stdout, 'stderr': result.stderr, 'stdin_supplied': password is not None}
        row['commands'].append(record)
        save()
        if required:
            assert result.returncode == 0, (label, result.stderr)
        return result

    def stop_agent(label):
        recorded = agents(home, account.pw_uid)
        if label == 'stop-after-positive':
            assert len(recorded) == 1
        row.setdefault('agent_shutdowns', []).append({'label': label, 'recorded': recorded})
        command(label, ['/usr/bin/gpgconf', '--homedir', str(home), '--kill', 'gpg-agent'])
        deadline = time.monotonic() + 5
        while any(Path('/proc', str(item['pid'])).exists() for item in recorded):
            assert time.monotonic() < deadline, recorded
            time.sleep(0.05)
        assert not agents(home, account.pw_uid)
        row['agent_shutdowns'][-1]['processes_absent'] = True
        save()

    try:
        observed_uid = command('id', ['/usr/bin/id', '-u']).stdout.strip()
        assert int(observed_uid) == account.pw_uid
        common = ['/usr/bin/gpg', '--homedir', str(home), '--batch', '--yes', '--pinentry-mode', 'loopback']
        identity = 'Module Target <gpg-' + actor + ('-protected' if protected else '-plain') + '@example.test>'
        command('generate', common + ['--passphrase-fd', '0', '--quick-generate-key', identity, 'ed25519', 'sign', '0'], phrase)
        listed = command('secret-key-list', common + ['--with-colons', '--with-keygrip', '--list-secret-keys']).stdout
        fingerprints = [line.split(':')[9] for line in listed.splitlines() if line.startswith('fpr:')]
        grips = [line.split(':')[9] for line in listed.splitlines() if line.startswith('grp:')]
        assert len(fingerprints) == len(grips) == 1
        assert re.fullmatch('[A-F0-9]{40}', fingerprints[0]) and re.fullmatch('[A-F0-9]{40}', grips[0])
        row.update(fingerprint=fingerprints[0], keygrip=grips[0])
        private = home / 'private-keys-v1.d' / (grips[0] + '.key')
        assert private.is_file() and private.stat().st_uid == account.pw_uid
        assert private.stat().st_mode & 0o777 == 0o600
        assert (b'protected-private-key' in private.read_bytes()) == protected
        message = directory / 'message.txt'
        message.write_bytes(b'Module target native GnuPG signature proof\n')
        os.chown(message, account.pw_uid, account.pw_gid)
        signature = directory / 'signature.asc'
        command('sign', common + ['--passphrase-fd', '0', '--status-fd', '1', '--armor', '--detach-sign', '--output', str(signature), str(message)], phrase)
        assert signature.is_file() and signature.stat().st_uid == account.pw_uid
        verified = command('verify', common + ['--status-fd', '1', '--verify', str(signature), str(message)])
        assert '[GNUPG:] VALIDSIG ' + fingerprints[0] + ' ' in verified.stdout
        stop_agent('stop-after-positive')
        if protected:
            wrong_signature = directory / 'wrong-signature.asc'
            rejected = command('wrong-passphrase', common + ['--passphrase-fd', '0', '--status-fd', '1', '--armor', '--detach-sign', '--output', str(wrong_signature), str(message)], 'module-target-gpg-wrong', required=False)
            assert rejected.returncode != 0
            assert not wrong_signature.exists() or wrong_signature.stat().st_size == 0
            row['wrong_passphrase_rejected_without_cache'] = True
            stop_agent('stop-after-negative')
        row['files'] = {}
        for path in sorted(home.rglob('*')):
            if not path.is_file():
                assert path.is_dir(), str(path)
                continue
            raw = path.read_bytes()
            row['files'][str(path.relative_to(home))] = {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest(),
                                                         'uid': path.stat().st_uid, 'mode': oct(path.stat().st_mode & 0o777),
                                                         'base64': base64.b64encode(raw).decode()}
        assert 'pubring.kbx' in row['files'] and 'private-keys-v1.d/' + grips[0] + '.key' in row['files']
        row['native_passed'] = True
    finally:
        try:
            stop_agent('final-agent-stop')
        finally:
            if homedir is not None and not (keep and row.get('native_passed')):
                assert home == Path(account.pw_dir) / '.gnupg' and not home.is_symlink()
                shutil.rmtree(home)
            row['home_retained_for_owning_case'] = homedir is not None and home.exists()
            shutil.rmtree(directory)
            row['temporary_directory_absent'] = not directory.exists()
            save()


if __name__ == '__main__':
    try:
        assert os.geteuid() == 0
        data['packages'] = subprocess.check_output(['dpkg-query', '-W', '-f=${Package}=${Version}\n', 'gnupg', 'gpg', 'gpg-agent', 'gpgconf', 'python3'], text=True)
        data['gpg_version'] = subprocess.check_output(['/usr/bin/gpg', '--version'], text=True)
        data['binary_sha256'] = {name: hashlib.sha256(Path(name).read_bytes()).hexdigest() for name in ['/usr/bin/gpg', '/usr/bin/gpgconf', '/usr/bin/gpg-agent']}
        for actor in ['root', 'labuser']:
            for protected in [False, True]:
                control(actor, protected)
        data['native_passed'] = True
    except BaseException as error:
        data['failure'] = {'type': type(error).__name__, 'message': str(error)}
    finally:
        save()
        print(json.dumps(data))
    raise SystemExit(0 if data['native_passed'] else 1)
