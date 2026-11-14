"""Small STARTTLS transport adapters; all TLS bytes pass to real s_server.

These test the module's six upgrade dialogs, not full production mail, XMPP,
FTP or PostgreSQL implementations. No heartbeat response is generated here.
"""
from pathlib import Path
import base64
import json
import selectors
import signal
import socket
import socketserver
import struct
import threading
import time

root = Path('/tmp/heartbleed-lab')
lock = threading.Lock()


def exact(stream, length):
    result = b''
    while len(result) < length:
        part = stream.recv(length - len(result))
        if not part:
            raise EOFError('Upgrade ended early')
        result += part
    return result


def line(stream):
    result = b''
    while not result.endswith(b'\r\n'):
        result += exact(stream, 1)
        if len(result) > 1024:
            raise ValueError('Upgrade line exceeded bound')
    return result


def xml(stream, terminator):
    result = b''
    while not result.endswith(terminator):
        result += exact(stream, 1)
        if len(result) > 2048:
            raise ValueError('Upgrade XML exceeded bound')
    return result


class Adapter(socketserver.BaseRequestHandler):
    def handle(self):
        stream = self.request
        stream.settimeout(5)
        protocol = self.server.protocol
        evidence = {'protocol': protocol, 'port': self.server.server_address[1], 'backend': self.server.backend, 'peer': list(self.client_address), 'at': time.time(), 'upgraded': False, 'request_bytes': 0, 'response_bytes': 0}
        try:
            if protocol == 'SMTP':
                stream.sendall(b'220 heartbleed.invalid ESMTP\r\n')
                assert line(stream).startswith(b'EHLO ')
                stream.sendall(b'250-heartbleed.invalid\r\n250 STARTTLS\r\n')
                assert line(stream) == b'STARTTLS\r\n'
                stream.sendall(b'220 Ready to start TLS\r\n')
            elif protocol == 'IMAP':
                stream.sendall(b'* OK heartbleed.invalid IMAP4rev1\r\n')
                assert line(stream) == b'a001 CAPABILITY\r\n'
                stream.sendall(b'* CAPABILITY IMAP4rev1 STARTTLS\r\na001 OK CAPABILITY completed\r\n')
                assert line(stream) == b'a002 STARTTLS\r\n'
                stream.sendall(b'a002 OK Begin TLS negotiation now\r\n')
            elif protocol == 'POP3':
                stream.sendall(b'+OK heartbleed.invalid POP3\r\n')
                assert line(stream) == b'CAPA\r\n'
                stream.sendall(b'+OK Capability list follows\r\nSTLS\r\n.\r\n')
                assert line(stream) == b'STLS\r\n'
                stream.sendall(b'+OK Begin TLS negotiation\r\n')
            elif protocol == 'FTP':
                stream.sendall(b'220 heartbleed.invalid FTP\r\n')
                assert line(stream) == b'AUTH TLS\r\n'
                stream.sendall(b'234 AUTH TLS successful\r\n')
            elif protocol == 'POSTGRES':
                assert exact(stream, 8) == struct.pack('!II', 8, 80877103)
                stream.sendall(b'S')
            elif protocol == 'JABBER':
                request = xml(stream, b'>')
                assert request.startswith(b'<stream:stream ') and b"to='localhost'" in request
                stream.sendall(b"<stream:stream from='localhost' xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams' version='1.0'><stream:features><starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'/></stream:features>")
                assert xml(stream, b'/>') == b"<starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>"
                stream.sendall(b"<proceed xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>")
            else:
                raise ValueError('Unknown protocol')
            evidence['upgraded'] = True
            with socket.create_connection(('127.0.0.1', self.server.backend), timeout=3) as backend:
                with selectors.DefaultSelector() as selector:
                    selector.register(stream, selectors.EVENT_READ, (backend, 'request_bytes'))
                    selector.register(backend, selectors.EVENT_READ, (stream, 'response_bytes'))
                    while True:
                        events = selector.select(5)
                        if not events:
                            break
                        closed = False
                        for key, mask in events:
                            part = key.fileobj.recv(65536)
                            if not part:
                                closed = True
                                break
                            destination, counter = key.data
                            destination.sendall(part)
                            evidence[counter] += len(part)
                        if closed:
                            break
        except (AssertionError, EOFError, OSError, ValueError) as error:
            evidence['error'] = repr(error)
        finally:
            with lock:
                with (root / 'upgrade-connections.jsonl').open('a') as output:
                    output.write(json.dumps(evidence) + '\n')


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


servers = []
for base, backend in [(10400, 10100), (11400, 10200)]:
    for offset, protocol in enumerate(['SMTP', 'IMAP', 'JABBER', 'POP3', 'FTP', 'POSTGRES']):
        server = Server(('0.0.0.0', base + offset * 100), Adapter)
        server.protocol = protocol
        server.backend = backend
        servers.append(server)
        threading.Thread(target=server.serve_forever, daemon=True).start()
signal.pause()
