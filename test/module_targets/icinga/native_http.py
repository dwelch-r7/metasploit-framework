"""Independent standard-library HTTP requests; no Framework module imports."""
import base64
import hashlib
import http.client
import json
import socket
import sys
import urllib.parse

host, port, prefix = sys.argv[1], int(sys.argv[2]), sys.argv[3]
unrelated_port = int(sys.argv[4])
records = {}


def request(port_number, path, redirects=0):
    with socket.create_connection((host, port_number), timeout=5) as stream:
        stream.settimeout(8)
        # Send the observed request-target bytes directly, including explicit raw
        # UTF-8 and invalid-space controls. Python parses the genuine response.
        stream.sendall(b'GET ' + path.encode() + b' HTTP/1.1\r\nHost: target\r\nConnection: close\r\n\r\n')
        response = http.client.HTTPResponse(stream)
        response.begin()
        body = response.read()
        row = {
            'port': port_number, 'path': path, 'status': response.status,
            'headers': dict(response.getheaders()), 'bytes': len(body),
            'sha256': hashlib.sha256(body).hexdigest(),
            'body_base64': base64.b64encode(body).decode()
        }
    if response.status in [301, 302, 303, 307, 308] and redirects < 5:
        destination = urllib.parse.urljoin(path, response.getheader('Location'))
        if urllib.parse.urlsplit(destination).netloc:
            raise ValueError('Native redirect unexpectedly leaves the controlled target')
        next_row = request(port_number, destination, redirects + 1)
        next_row['redirects'] = [row] + next_row.get('redirects', [])
        return next_row
    return row


records['home'] = request(port, prefix)
records['direct'] = request(port, prefix + 'lab/proof/proof.txt')
for name in ['proof.txt', 'whitespace.txt', 'binary.bin', 'empty.txt', 'space name.txt', 'unicode-Ω.txt', 'denied.txt', 'missing.txt', 'directory']:
    path = prefix + 'lib/icinga/icinga-php-thirdparty/lab/proof/' + name
    records[name] = request(port, path)
    if ' ' in name or 'Ω' in name:
        records[name + ':encoded'] = request(port, prefix + 'lib/icinga/icinga-php-thirdparty/lab/proof/' + urllib.parse.quote(name))
records['unrelated_home'] = request(unrelated_port, '/')
records['unrelated_read'] = request(unrelated_port, '/lib/icinga/icinga-php-thirdparty/lab/proof/proof.txt')
try:
    socket.create_connection((host, 1), timeout=3).close()
except ConnectionRefusedError:
    records['refused'] = True
else:
    raise ValueError('Native refused port unexpectedly accepts connections')
print(json.dumps(records))
