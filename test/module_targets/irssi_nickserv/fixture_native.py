"""Draft genuine NickServ controls. No native execution has yet qualified these."""
from pathlib import Path
import base64
import fcntl
import hashlib
import json
import os
import pty
import pwd
import re
import select
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import termios
import time

ACTION = sys.argv[1]
assert ACTION in ['bootstrap', 'probe', 'drop', 'case']
FIXTURES = Path('/opt/irssi-fixtures')
CATALOGUE = json.loads((FIXTURES / 'catalogue.json').read_text())
PASSWORD = 'module-target-nickserv-password'
ARTIFACT = Path('/opt/native-artifacts', 'nickserv-' + ACTION + '.json')
data = {'action': ACTION, 'native_passed': False, 'owner_calls': 0, 'connections': [], 'controls': []}


def save():
    ARTIFACT.write_text(json.dumps(data, indent=2) + '\n')


def clean(text):
    return text.translate({ord(char): None for char in '\x02\x0f\x16\x1d\x1f'})


def service_snapshot():
    packages = subprocess.check_output(['dpkg-query', '-W', '-f=${Package}=${Version}\n', 'irssi', 'ngircd', 'atheme-services', 'python3'], text=True)
    assert dict(line.split('=', 1) for line in packages.splitlines()) == {
        'irssi': '1.2.3-1ubuntu4', 'ngircd': '26.1-1',
        'atheme-services': '7.2.12-1', 'python3': '3.10.6-1~22.04.1'}
    services = []
    for row in json.loads(Path('/opt/native-artifacts/service-launch.json').read_text()):
        process = Path('/proc', str(row['pid']))
        executable = Path(row['argv'][0]).resolve(strict=True)
        status = dict(line.split(':', 1) for line in (process / 'status').read_text().splitlines())
        uid = int(status['Uid'].split()[1])
        expected = 65534 if executable.name == 'ngircd' else pwd.getpwnam('irc').pw_uid
        assert uid == expected and status['Name'].strip() == executable.name[:15]
        assert status['State'].strip().split()[0] != 'Z'
        fields = (process / 'stat').read_text().rsplit(')', 1)[1].split()
        # Privilege-dropping ngIRCd is not dumpable. Bind its recorded launch PID
        # to kernel name/UID/start time and the package file, without ptrace caps.
        services.append({'pid': row['pid'], 'launched_executable': str(executable), 'uid': uid,
                         'kernel_name': status['Name'].strip(), 'starttime': int(fields[19]),
                         'launched_package_binary_sha256': hashlib.sha256(executable.read_bytes()).hexdigest(),
                         'proc_exe_attestation': False})
    assert len(services) == 2
    paths = ['/etc/passwd', '/etc/group', '/etc/ngircd/module-target.conf', '/etc/atheme/module-target.conf']
    paths += [str(path) for path in sorted(FIXTURES.iterdir()) if path.is_file()]
    resources = {name: dict(line.split() for line in Path('/sys/fs/cgroup', name).read_text().splitlines())
                 for name in ['memory.events', 'pids.events']}
    assert resources['memory.events']['oom'] == resources['memory.events']['oom_kill'] == '0'
    assert resources['pids.events']['max'] == '0'
    return {'packages': packages, 'services': services,
            'files': {path: hashlib.sha256(Path(path).read_bytes()).hexdigest() for path in paths},
            'resources': resources}


class NativeConnection:
    def __init__(self):
        self.row = {'sent': [], 'received': []}
        data['connections'].append(self.row)
        self.socket = socket.create_connection(('127.0.0.1', 6667), 5)
        self.buffer = ''

    def send(self, line):
        assert '\r' not in line and '\n' not in line
        self.row['sent'].append(line)
        save()
        self.socket.sendall((line + '\r\n').encode())

    def until(self, predicate, seconds=20):
        seen = []
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            if '\n' not in self.buffer:
                self.socket.settimeout(max(0.01, deadline - time.monotonic()))
                chunk = self.socket.recv(65536)
                assert chunk, 'Genuine IRC connection closed before proof'
                self.buffer += chunk.decode(errors='replace')
                continue
            line, self.buffer = self.buffer.split('\n', 1)
            line = line.rstrip('\r')
            self.row['received'].append(line)
            seen.append(line)
            save()
            if line.startswith('PING '):
                self.send('PONG ' + line[5:])
            if predicate(clean(line)):
                return clean(line)
            assert not any(code in line for code in [' 432 ', ' 433 ']), line
        raise TimeoutError('No genuine IRC/NickServ proof: ' + repr(seen))

    def connect(self):
        self.send('NICK labguest')
        self.send('USER labguest 0 * :Module target account control')
        self.until(lambda line: ':irc.module.test 001 labguest ' in line)
        self.send('PRIVMSG NickServ :STATUS')
        line = self.until(lambda line: line.startswith(':NickServ!') and 'You are ' in line and 'logged in' in line)
        assert 'You are not logged in.' in line, 'Fresh connection was already authenticated'

    def close(self):
        try:
            self.send('QUIT :module-target-native-control')
            self.socket.shutdown(socket.SHUT_WR)
            self.socket.settimeout(5)
            while self.socket.recv(65536):
                pass
            self.row['peer_closed_after_quit'] = True
        finally:
            self.socket.close()
            self.row['socket_closed'] = True
            save()


def account_control():
    connection = NativeConnection()
    try:
        connection.connect()
        if ACTION == 'bootstrap':
            connection.send('PRIVMSG NickServ :INFO labguest')
            connection.until(lambda line: line.startswith(':NickServ!') and 'labguest is not registered.' in line)
            connection.send('PRIVMSG NickServ :REGISTER ' + PASSWORD + ' nickserv@example.test')
            connection.until(lambda line: line.startswith(':NickServ!') and 'labguest is now registered to nickserv@example.test' in line)
            connection.send('PRIVMSG NickServ :STATUS')
            connection.until(lambda line: line.startswith(':NickServ!') and 'You are logged in as labguest.' in line)
            data['account_created_through_native_service'] = True
        else:
            command = 'DROP labguest ' + PASSWORD
            connection.send('PRIVMSG NickServ :' + command)
            line = connection.until(lambda line: line.startswith(':NickServ!') and 'Please confirm by replying with ' in line)
            challenge = re.search(re.escape(command) + r' (\S+)', line).group(1)
            connection.send('PRIVMSG NickServ :' + command + ' ' + challenge)
            connection.until(lambda line: line.startswith(':NickServ!') and 'The account labguest has been dropped.' in line)
            connection.send('PRIVMSG NickServ :INFO labguest')
            connection.until(lambda line: line.startswith(':NickServ!') and 'labguest is not registered.' in line)
            data['account_removed_and_absent'] = True
    finally:
        connection.close()


def control(actor, name, case, config_path=None):
    account = pwd.getpwnam(actor)
    raw = (FIXTURES / name).read_bytes()
    assert hashlib.sha256(raw).hexdigest() == case['sha256']
    assert b'password =' not in raw, 'Server-password fallback would mask NickServ omission'
    row = {'actor': actor, 'uid': account.pw_uid, 'case': name, 'file_sha256': case['sha256'], 'operator_signals': []}
    data['controls'].append(row)
    save()
    with tempfile.TemporaryDirectory(prefix='native-irssi-nickserv-') as directory:
        home = Path(directory)
        os.chown(home, account.pw_uid, account.pw_gid)
        config = Path(config_path) if config_path else home / 'config'
        if config_path is None:
            config.write_bytes(raw)
            os.chown(config, account.pw_uid, account.pw_gid)
            config.chmod(0o600)
        assert config.read_bytes() == raw
        wire_file = home / 'wire.log'
        master, slave = pty.openpty()
        fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack('HHHH', 30, 120, 0, 0))
        env = {key: value for key, value in os.environ.items() if not key.startswith('IRC')}
        env.update(HOME=directory, USER=actor, LOGNAME=actor, TERM='xterm', LC_ALL='C')

        def identity():
            os.setsid()
            fcntl.ioctl(0, termios.TIOCSCTTY, 0)
            os.setgroups([])
            os.setgid(account.pw_gid)
            os.setuid(account.pw_uid)

        args = ['irssi', '--noconnect', '--config=' + str(config), '--home=' + directory]
        row['argv'] = args
        process = subprocess.Popen(args, stdin=slave, stdout=slave, stderr=slave, cwd=directory, env=env, preexec_fn=identity)
        os.close(slave)
        terminal = bytearray()

        def pump():
            if select.select([master], [], [], 0.1)[0]:
                try:
                    terminal.extend(os.read(master, 65536))
                except OSError as error:
                    if error.errno != 5:
                        raise

        def until(predicate, start=0):
            deadline = time.monotonic() + 20
            while True:
                pump()
                wire = clean(wire_file.read_text(errors='replace')) if wire_file.exists() else ''
                if predicate(wire[start:]):
                    return wire
                assert process.poll() is None, 'Irssi exited before proof'
                assert time.monotonic() < deadline, 'No genuine NickServ proof: ' + wire

        try:
            deadline = time.monotonic() + 10
            while not terminal:
                assert process.poll() is None and time.monotonic() < deadline
                pump()
            command = '/connect -rawlog ' + str(wire_file) + ' LabNet\r'
            row['terminal_connect_command'] = command
            os.write(master, command.encode())
            wire = until(lambda text: ':irc.module.test 001 labguest ' in text)
            if case['command']:
                verdict = 'You are now identified for labguest.' if case['expected_identified'] else 'Invalid password for labguest.'
                wire = until(lambda text: verdict in text)
                sent = case['command'].lstrip('/^').split(None, 2)[2]
                assert ('PRIVMSG nickserv :' + sent).lower() in wire.lower()
            else:
                assert 'privmsg nickserv :identify' not in wire.lower()
            previous = len(wire)
            os.write(master, b'/msg NickServ STATUS\r')
            status = 'You are logged in as labguest.' if case['expected_identified'] else 'You are not logged in.'
            wire = until(lambda text: status in text, start=previous)
            row.update(identified=case['expected_identified'], status_verified=True, wire=wire)
            os.write(master, b'/rawlog close\r/quit module-target-native\r')
            deadline = time.monotonic() + 10
            while process.poll() is None and time.monotonic() < deadline:
                pump()
            assert process.poll() == 0
            assert config.read_bytes() == raw
            row['configuration_unchanged'] = True
        finally:
            if process.poll() is None:
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
            row.update(exit=process.returncode, terminal_base64=base64.b64encode(terminal).decode(),
                       wire=wire_file.read_text(errors='replace') if wire_file.exists() else '',
                       process_absent=not Path('/proc', str(process.pid)).exists())
            os.close(master)
            save()
    row['temporary_home_absent'] = not home.exists()
    assert row['process_absent'] and row['temporary_home_absent'] and row['exit'] == 0 and not row['operator_signals']
    save()


if __name__ == '__main__':
    save()
    try:
        data['before'] = service_snapshot()
        if ACTION == 'probe':
            for actor in ['root', 'labuser']:
                for name, case in CATALOGUE.items():
                    control(actor, name, case)
        else:
            account_control()
        data['after'] = service_snapshot()
        assert data['before'] == data['after']
        data['native_passed'] = True
    except BaseException as error:
        data['failure'] = {'type': type(error).__name__, 'message': str(error)}
        raise
    finally:
        save()
    print(json.dumps(data))
