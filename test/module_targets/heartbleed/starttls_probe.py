"""Independent standard-library client for six upgrade transport dialogs."""
from pathlib import Path
import json
import socket
import ssl
import struct
import sys
import urllib.request

from wire import exact, heartbeat, root

after = sys.argv[1:] == ['after']
PROTOCOLS = ['SMTP', 'IMAP', 'JABBER', 'POP3', 'FTP', 'POSTGRES']


def until(stream, ending):
    response = b''
    while not response.endswith(ending):
        response += exact(stream, 1)
        assert len(response) <= 4096
    return response


def upgrade(stream, protocol):
    if protocol == 'SMTP':
        assert until(stream, b'\r\n').startswith(b'220 ')
        stream.sendall(b'EHLO native.invalid\r\n')
        assert b'STARTTLS' in until(stream, b'250 STARTTLS\r\n')
        stream.sendall(b'STARTTLS\r\n')
        assert until(stream, b'\r\n').startswith(b'220 ')
    elif protocol == 'IMAP':
        assert until(stream, b'\r\n').startswith(b'* OK ')
        stream.sendall(b'a001 CAPABILITY\r\n')
        assert b'STARTTLS' in until(stream, b'a001 OK CAPABILITY completed\r\n')
        stream.sendall(b'a002 STARTTLS\r\n')
        assert until(stream, b'\r\n').startswith(b'a002 OK ')
    elif protocol == 'POP3':
        assert until(stream, b'\r\n').startswith(b'+OK ')
        stream.sendall(b'CAPA\r\n')
        assert b'STLS\r\n' in until(stream, b'.\r\n')
        stream.sendall(b'STLS\r\n')
        assert until(stream, b'\r\n').startswith(b'+OK ')
    elif protocol == 'FTP':
        assert until(stream, b'\r\n').startswith(b'220 ')
        stream.sendall(b'AUTH TLS\r\n')
        assert until(stream, b'\r\n').startswith(b'234 ')
    elif protocol == 'POSTGRES':
        stream.sendall(struct.pack('!II', 8, 80877103))
        assert exact(stream, 1) == b'S'
    elif protocol == 'JABBER':
        stream.sendall(b"<stream:stream xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams' version='1.0' to='localhost'>")
        assert b"<starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'" in until(stream, b'</stream:features>')
        stream.sendall(b"<starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>")
        assert until(stream, b'/>').startswith(b'<proceed ')
    else:
        raise ValueError('Unknown upgrade protocol')


def main():
    record = {'status': 'running', 'cases': [], 'normal_tls': []}
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    context.set_ciphers('AES128-SHA:@SECLEVEL=0')
    try:
        for base, vulnerable in [(10400, True), (11400, False)]:
            for offset, protocol in enumerate(PROTOCOLS):
                port = base + offset * 100
                for valid in ([False] if after else [True, False]):
                    outcome = heartbeat(port, 0x0303, 8192, valid=valid, upgrade=lambda stream: upgrade(stream, protocol))
                    record['cases'].append({'port': port, 'protocol': protocol, 'valid': valid, 'outcome': outcome})
                    if valid:
                        assert outcome.get('valid_echo'), (port, outcome)
                    elif vulnerable:
                        assert outcome.get('extra_bytes') == 8192, (port, outcome)
                    else:
                        assert not outcome.get('received_payload_bytes'), (port, outcome)
                with socket.create_connection(('127.0.0.1', port), timeout=3) as raw:
                    upgrade(raw, protocol)
                    with context.wrap_socket(raw, server_hostname='heartbleed.invalid') as secure:
                        record['normal_tls'].append({'port': port, 'protocol': protocol, 'version': secure.version()})
        with urllib.request.urlopen('http://127.0.0.1:2525/', timeout=2) as response:
            assert response.status == 200 and response.read() == b'Heartbleed unrelated HTTP control\n'
            record['unrelated_http'] = True
        record['status'] = 'passed'
    finally:
        (root / 'upgrade-native.json').write_text(json.dumps(record, indent=2) + '\n')
    print(json.dumps(record))


if __name__ == '__main__':
    main()
