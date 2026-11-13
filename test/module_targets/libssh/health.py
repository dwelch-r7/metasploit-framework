"""Read native protocol greetings; no invented SSH responses."""
import socket

for port in range(2222, 2229):
    with socket.create_connection(('127.0.0.1', port), timeout=2) as stream:
        stream.settimeout(2)
        assert stream.recv(256).startswith(b'SSH-2.0-')
with socket.create_connection(('127.0.0.1', 2525), timeout=2) as stream:
    assert stream.recv(256).startswith(b'220 ')
