"""Use actual Irssi terminal/rawlog output against the real password server."""
from pathlib import Path
import base64
import fcntl
import hashlib
import json
import os
import pty
import pwd
import select
import signal
import struct
import subprocess
import sys
import tempfile
import termios
import time

phase = sys.argv[1]
assert phase in ['before', 'after', 'case']
fixtures = Path('/opt/irssi-fixtures')
catalogue = json.loads((fixtures / 'catalogue.json').read_text())
artifact = Path('/opt/native-artifacts', 'native-' + phase + '.json')
data = {'phase': phase, 'native_passed': False, 'owner_calls': 0, 'controls': [],
        'fixtures': {name: {'sha256': hashlib.sha256((fixtures / name).read_bytes()).hexdigest(),
                            'base64': base64.b64encode((fixtures / name).read_bytes()).decode()} for name in catalogue}}

def save():
    artifact.write_text(json.dumps(data, indent=2) + '\n')

def password_denied(wire):
    # Captured ngIRCd 26.1 registration rejection; not every server sends 464.
    return ' 464 ' in wire or '>> ERROR :Access denied: Bad password?' in wire.splitlines()

def control(actor, name, case, config_path=None):
    account = pwd.getpwnam(actor)
    raw = (fixtures / name).read_bytes()
    assert hashlib.sha256(raw).hexdigest() == case['sha256']
    row = {'actor': actor, 'uid': account.pw_uid, 'case': name, 'file_sha256': case['sha256'],
           'expected_authenticated': case['authenticated'], 'operator_signals': []}
    data['controls'].append(row)
    save()
    with tempfile.TemporaryDirectory(prefix='native-irssi-') as directory:
        home = Path(directory)
        os.chown(home, account.pw_uid, account.pw_gid)
        config = Path(config_path) if config_path else home / 'config'
        if config_path is None:
            config.write_bytes(raw)
            os.chown(config, account.pw_uid, account.pw_gid)
            config.chmod(0o600)
        else:
            assert config.read_bytes() == raw
        log = home / 'wire.log'
        master, slave = pty.openpty()
        fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack('HHHH', 30, 120, 0, 0))
        env = {key: value for key, value in os.environ.items() if not key.startswith('IRC')}
        env.update(HOME=directory, USER=actor, LOGNAME=actor, TERM='xterm', LC_ALL='C')
        args = ['irssi', '--noconnect', '--config=' + str(config), '--home=' + directory]
        row['argv'] = args

        def identity():
            os.setsid()
            fcntl.ioctl(0, termios.TIOCSCTTY, 0)
            os.setgroups([])
            os.setgid(account.pw_gid)
            os.setuid(account.pw_uid)

        process = subprocess.Popen(args, stdin=slave, stdout=slave, stderr=slave,
                                   cwd=directory, env=env, preexec_fn=identity)
        os.close(slave)
        terminal = bytearray()

        def pump(seconds=0.1):
            if select.select([master], [], [], seconds)[0]:
                try:
                    chunk = os.read(master, 65536)
                except OSError as error:
                    if error.errno != 5:
                        raise
                    return
                terminal.extend(chunk)

        try:
            deadline = time.monotonic() + 10
            while not terminal:
                assert process.poll() is None, process.returncode
                assert time.monotonic() < deadline, 'No native Irssi terminal output'
                pump()
            command = '/connect -rawlog ' + str(log) + ' LabNet\r'
            row['terminal_connect_command'] = command
            os.write(master, command.encode())
            deadline = time.monotonic() + 20
            while True:
                pump()
                wire = log.read_text(errors='replace') if log.exists() else ''
                if ':irc.module.test 001 ' in wire or password_denied(wire):
                    break
                assert not any(code in wire for code in [' 432 ', ' 433 ']), wire
                assert process.poll() is None, 'Irssi exited before protocol proof'
                assert time.monotonic() < deadline, 'No native IRC welcome/password denial in rawlog'
            row['wire'] = wire
            row['authenticated'] = ':irc.module.test 001 ' in wire
            assert row['authenticated'] == case['authenticated'], wire
            if case['authenticated']:
                assert 'module-target-irc-password' in wire, 'Native rawlog did not expose configured PASS'
            else:
                assert password_denied(wire) and ':irc.module.test 001 ' not in wire
                if name == 'wrong.config':
                    assert 'module-target-wrong-password' in wire
                if name == 'commented.config':
                    assert 'module-target-comment-password' not in wire
            os.write(master, b'/rawlog close\r/quit module-target-native\r')
            deadline = time.monotonic() + 10
            while process.poll() is None and time.monotonic() < deadline:
                pump()
            assert process.poll() == 0, 'Native Irssi did not exit cleanly'
            assert config.read_bytes() == raw, 'Irssi changed the supplied configuration'
            row['exit'] = process.returncode
            row['configuration_unchanged'] = True
        finally:
            if process.poll() is None:
                row['graceful_recovery_requested'] = True
                os.write(master, b'/quit module-target-native-recovery\r')
                deadline = time.monotonic() + 5
                while process.poll() is None and time.monotonic() < deadline:
                    pump()
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGTERM)
                row['operator_signals'].append('SIGTERM')
                try:
                    process.wait(5)
                except subprocess.TimeoutExpired:
                    os.killpg(process.pid, signal.SIGKILL)
                    row['operator_signals'].append('SIGKILL')
                    process.wait(5)
            row['exit'] = process.returncode
            row['terminal_base64'] = base64.b64encode(terminal).decode()
            row['wire'] = log.read_text(errors='replace') if log.exists() else ''
            row['process_absent'] = not Path('/proc', str(process.pid)).exists()
            os.close(master)
            save()
    row['temporary_home_absent'] = not home.exists()
    assert row['process_absent'] and row['temporary_home_absent'] and not row['operator_signals']
    save()

if __name__ == '__main__':
    save()
    try:
        for actor in ['root', 'labuser']:
            for name, case in catalogue.items():
                control(actor, name, case)
        data['packages'] = subprocess.check_output(['dpkg-query', '-W', '-f=${Package}=${Version}\n', 'irssi', 'ngircd', 'python3'], text=True)
        assert dict(line.split('=', 1) for line in data['packages'].splitlines()) == {
            'irssi': '1.2.3-1ubuntu4', 'ngircd': '26.1-1', 'python3': '3.10.6-1~22.04.1'}
        data['files'] = {name: hashlib.sha256(Path(name).read_bytes()).hexdigest()
                         for name in ['/etc/passwd', '/etc/group', '/etc/ngircd/module-target.conf']}
        data['server_pid'] = int(Path('/run/module-target-ngircd/server.pid').read_text())
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
