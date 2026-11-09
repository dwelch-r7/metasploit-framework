"""Independent RFB handshake/authentication and actual framebuffer initialization.

Wire format: https://datatracker.ietf.org/doc/html/rfc6143 sections 7.1-7.3 and
appendix A. DES uses the installed PyCryptodome package, not Framework code.
"""
import base64
import json
import socket
import struct
import sys
from Cryptodome.Cipher import DES


def receive(sock, count):
    data = b''
    while len(data) < count:
        part = sock.recv(count - len(data))
        if not part:
            raise EOFError(f'RFB closed after {len(data)} of {count} bytes')
        data += part
    return data


def probe(host, port, version, password):
    report = dict(host=host, port=port, version=version)
    with socket.create_connection((host, port), timeout=5) as sock:
        sock.settimeout(5)
        banner = receive(sock, 12)
        assert banner == f'RFB 003.{version:03d}\n'.encode(), banner
        report['banner'] = banner.decode()
        sock.sendall(banner)
        if version == 3:
            security = struct.unpack('!I', receive(sock, 4))[0]
            offered = [security]
        else:
            count = receive(sock, 1)[0]
            assert count > 0, count
            offered = list(receive(sock, count))
            security = 2 if 2 in offered else 1
            sock.sendall(bytes([security]))
        report['security_types'] = offered
        assert security in (1, 2), security
        if security == 2:
            challenge = receive(sock, 16)
            # RFB reverses the bits of each byte of the eight-byte DES key.
            key = password.encode('ascii')[:8].ljust(8, b'\0')
            key = bytes(int(f'{value:08b}'[::-1], 2) for value in key)
            sock.sendall(DES.new(key, DES.MODE_ECB).encrypt(challenge))
            report['challenge'] = base64.b64encode(challenge).decode()
        status = 0
        if security == 2 or version >= 8:
            status = struct.unpack('!I', receive(sock, 4))[0]
        report['status'] = status
        if status != 0:
            return report
        sock.sendall(b'\1')
        header = receive(sock, 24)
        width, height = struct.unpack('!HH', header[:4])
        name_length = struct.unpack('!I', header[20:24])[0]
        assert name_length < 1024, name_length
        name = receive(sock, name_length).decode()
        assert (width, height, name) == (320, 240, 'ModuleTargetVNC'), (width, height, name)
        report.update(width=width, height=height, desktop=name)
    return report


if __name__ == '__main__':
    host, port, version, password = sys.argv[1:]
    print(json.dumps(probe(host, int(port), int(version), password)))
