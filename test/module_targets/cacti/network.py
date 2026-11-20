"""Check the stock Cacti runtime's callback transport without requiring nc."""
import json
import os
import socket
import sys
import threading

import native as target


def callback():
    hosts = target.command('app', 'cat', '/etc/hosts').decode().splitlines()
    addresses = [row.split()[0] for row in hosts if 'host.docker.internal' in row.split()[1:] and ':' not in row.split()[0]]
    target.check('one-configured-ipv4-host-gateway', len(addresses) == 1)
    host = addresses[0]
    token = 'module-target-cacti-transport-' + str(os.getpid())
    server = socket.socket()
    server.bind(('0.0.0.0', 0))
    server.listen(1)
    server.settimeout(10)
    state = {'host': host, 'bind': '0.0.0.0', 'port': server.getsockname()[1]}

    def receive():
        try:
            with server.accept()[0] as peer:
                peer.settimeout(10)
                response = bytearray()
                while response.count(b'\n') < 3:
                    chunk = peer.recv(1024)
                    if not chunk:
                        raise EOFError('Client closed before the complete transport proof')
                    response.extend(chunk)
                state['response'] = response.decode()
                peer.sendall((token + '-ack\n').encode())
                state['eof'] = peer.recv(1) == b''
        except Exception as error:
            state['error'] = {'type': type(error).__name__, 'message': str(error)}

    thread = threading.Thread(target=receive, daemon=True)
    thread.start()
    try:
        script = 'exec 3<>"/dev/tcp/$1/$2"; printf "%s\\n" "$3" >&3; id -u >&3; printf "%s\\n" "$$" >&3; IFS= read -r answer <&3; [ "$answer" = "$3-ack" ]; result=$?; exec 3<&-; exec 3>&-; exit "$result"'
        target.command('app', 'bash', '-c', script, 'native-cacti-transport', host, str(state['port']), token, timeout=18)
        thread.join(2)
        target.check('callback-thread-finished', not thread.is_alive())
        target.check('callback-eof-no-error', state.get('eof') is True and 'error' not in state)
        lines = state['response'].splitlines()
        target.check('callback-token-and-actual-uid', len(lines) == 3 and lines[:2] == [token, str(target.expected_uid)])
        pid = int(lines[2])
        target.check('callback-real-process', pid > 1)
        target.command('app', 'sh', '-c', '[ ! -e "/proc/$1" ]', 'closed-native-process', str(pid))
        return state
    finally:
        target.record['callback'] = state
        server.close()
        thread.join(12)


try:
    target.resources('before-network')
    data = callback()
    target.resources('after-network')
    target.record.update(passed=True, data=data)
except Exception as error:
    target.record.update(passed=False, error={'type': type(error).__name__, 'message': str(error)})
finally:
    (target.artifacts / 'cacti-network-callback.json').write_text(json.dumps(target.record, indent=2) + '\n')
    print(json.dumps(target.record))
if not target.record.get('passed'):
    raise SystemExit(1)
