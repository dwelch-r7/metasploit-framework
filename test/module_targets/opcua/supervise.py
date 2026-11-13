"""Run genuine upstream servers and bounded transparent TCP delivery faults."""
import base64
import hashlib
import json
from pathlib import Path
import signal
import socket
import struct
import subprocess
import threading
import time

root = Path('/tmp/opcua-lab')
root.mkdir(exist_ok=True)
stop = threading.Event()
lock = threading.Lock()
children = []
listeners = []


def journal(row):
    with lock, (root / 'proxy.jsonl').open('a') as output:
        output.write(json.dumps(dict(at=time.time(), **row)) + '\n')


def exact(stream, size):
    data = b''
    while len(data) < size:
        part = stream.recv(size - len(data))
        if not part:
            raise EOFError('Incomplete upstream frame')
        data += part
    return data


def connection(client, peer, backend_port, mode):
    record = dict(peer=peer, backend_port=backend_port, mode=mode)
    try:
        with client, socket.create_connection(('127.0.0.1', backend_port), timeout=3) as upstream:
            client.settimeout(8)
            upstream.settimeout(8)
            header = exact(client, 8)
            size = struct.unpack('<I', header[4:])[0]
            if not 8 <= size <= 65536:
                raise ValueError('HEL exceeds native control bound')
            hello = header + exact(client, size - 8)
            upstream.sendall(hello)
            header = exact(upstream, 8)
            size = struct.unpack('<I', header[4:])[0]
            if not 8 <= size <= 65536:
                raise ValueError('Upstream response exceeds control bound')
            response = header + exact(upstream, size - 8)
            record.update(hello_base64=base64.b64encode(hello).decode(), response_base64=base64.b64encode(response).decode(), response_sha256=hashlib.sha256(response).hexdigest())
            if mode == 'truncate':
                client.sendall(response[:8])
                record['sent_bytes'] = 8
                return
            client.sendall(response[:1])
            record['first_byte_at'] = time.time()
            time.sleep(0.15)
            client.sendall(response[1:])
            record['remaining_bytes_at'] = time.time()
            record['sent_bytes'] = len(response)
            # Only the first genuine frame is fragmented. All later bytes,
            # including the native client's real session/read, pass unchanged.
            import select
            while not stop.is_set():
                readable, _, _ = select.select([client, upstream], [], [], 5)
                if not readable:
                    break
                for source in readable:
                    data = source.recv(65536)
                    if not data:
                        return
                    (upstream if source is client else client).sendall(data)
    except (OSError, EOFError, ValueError) as error:
        record['transport_error'] = f'{type(error).__name__}: {error}'
    finally:
        journal(record)


def proxy(port, backend_port, mode):
    listener = socket.socket()
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(('0.0.0.0', port))
    listener.listen(16)
    listener.settimeout(0.5)
    listeners.append(listener)
    while not stop.is_set():
        try:
            client, peer = listener.accept()
        except socket.timeout:
            continue
        except OSError:
            break
        threading.Thread(target=connection, args=(client, peer, backend_port, mode), daemon=True).start()


def shutdown(signum, frame):
    stop.set()


signal.signal(signal.SIGTERM, shutdown)
signal.signal(signal.SIGINT, shutdown)
try:
    for port, buffer in [(4840, 65536), (4841, 16384), (4842, 4096)]:
        output = (root / f'server-{port}.log').open('w')
        child = subprocess.Popen(['/opt/opcua-bin/opcua-lab-server', str(port), str(buffer)], stdout=output, stderr=subprocess.STDOUT)
        children.append(child)
    output = (root / 'smtp.log').open('w')
    children.append(subprocess.Popen(['python3', '-m', 'smtpd', '-n', '-c', 'smtpd.DebuggingServer', '0.0.0.0:2525'], stdout=output, stderr=subprocess.STDOUT))
    (root / 'pids.json').write_text(json.dumps([child.pid for child in children]) + '\n')
    for port, backend, mode in [(5840, 4840, 'fragment'), (5842, 4842, 'fragment'), (5841, 4840, 'truncate')]:
        threading.Thread(target=proxy, args=(port, backend, mode), daemon=True).start()
    while not stop.wait(0.2):
        if any(child.poll() is not None for child in children):
            raise RuntimeError('Native service exited unexpectedly')
finally:
    stop.set()
    for listener in listeners:
        listener.close()
    for child in children:
        if child.poll() is None:
            child.terminate()
    for child in children:
        try:
            child.wait(timeout=5)
        except subprocess.TimeoutExpired:
            child.kill()
            child.wait()
