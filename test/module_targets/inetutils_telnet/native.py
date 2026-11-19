from pathlib import Path
import base64, errno, hashlib, json, os, pty, select, signal, subprocess, sys, time, uuid

fixed = sys.argv[1] == 'fixed'
port = sys.argv[2] if len(sys.argv) > 2 else '23'
results = []


def client(label, user, password=None, success=False, expected_uid=None):
    proof = Path('/tmp/module-target-inetutils-' + uuid.uuid4().hex)
    content = ('Native ' + label + ' "quoted" \\ path\nsecond line\n').encode()
    command = "printf '%s' '" + base64.b64encode(content).decode() + "' | base64 -d > " + str(proof) + "; id -u; exit\r"
    pid, fd = pty.fork()
    if pid == 0:
        env = dict(os.environ, USER=user, TERM='xterm')
        os.execve('/usr/bin/telnet', ['telnet', '-a', '-l', user, '127.0.0.1', port], env)
    output = bytearray()
    sent_password = sent_command = False
    deadline = time.monotonic() + 15
    started = time.monotonic()
    status = None
    try:
        while time.monotonic() < deadline:
            if select.select([fd], [], [], .1)[0]:
                try:
                    block = os.read(fd, 65536)
                except OSError as error:
                    if error.errno == errno.EIO:
                        break
                    raise
                if not block:
                    break
                output.extend(block)
            if password is not None and not sent_password and b'Password:' in output:
                os.write(fd, password.encode() + b'\r')
                sent_password = True
            # Only send proof after the genuine shell prompt. Echoed commands
            # are never accepted as proof: file bytes/UID are checked below.
            if not sent_command and (b'# ' in output[-200:] or b'$ ' in output[-200:]):
                os.write(fd, command.encode())
                sent_command = True
            if not success and any(marker in output for marker in [b'Login incorrect', b'login:']):
                break
            if sent_command and proof.exists() and proof.read_bytes() == content:
                break
        if proof.exists():
            observed = {'bytes_base64': base64.b64encode(proof.read_bytes()).decode(), 'uid': proof.stat().st_uid, 'sha256': hashlib.sha256(proof.read_bytes()).hexdigest()}
        else:
            observed = None
        record = {'label': label, 'user': user, 'sent_password': sent_password, 'sent_command': sent_command, 'expected_success': success, 'proof': observed, 'elapsed': time.monotonic()-started, 'transcript_base64': base64.b64encode(output).decode()}
        results.append(record)
        if success:
            assert observed and observed['bytes_base64'] == base64.b64encode(content).decode() and observed['uid'] == expected_uid, record
        else:
            assert observed is None and not sent_command, record
            assert any(marker in output for marker in [b'Login incorrect', b'Authentication failure', b'Password:', b'login:']) or (user == '-f module_target_absent' and b'Connection closed by foreign host.' in output), record
    finally:
        try:
            os.write(fd, b'exit\r')
        except OSError:
            pass
        try:
            os.kill(pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        os.close(fd)
        os.waitpid(pid, 0)
        if proof.exists():
            proof.unlink()


try:
    client('ordinary-password', 'labuser', 'module-target-telnet-password', True, 1001)
    client('wrong-password', 'labuser', 'incorrect-module-target-password')
    client('root-bypass-first', '-f root', success=not fixed, expected_uid=0)
    client('root-bypass-repeat', '-f root', success=not fixed, expected_uid=0)
    client('user-bypass', '-f labuser', success=not fixed, expected_uid=1001)
    client('missing-user', '-f module_target_absent')
finally:
    print(json.dumps({'fixed': fixed, 'results': results, 'packages': Path('/opt/module-target-packages.tsv').read_text(), 'binaries': Path('/opt/module-target-binaries.sha256').read_text()}), flush=True)
