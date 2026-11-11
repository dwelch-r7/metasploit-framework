"""Use the existing genuine Apache fixture for unrelated-product negatives."""
import base64
import hashlib
import http.client
import json
from pathlib import Path
import subprocess
import sys

runtime = json.loads(Path(sys.argv[1]).read_text())
phase = sys.argv[3]
endpoint = runtime['endpoints']['target']
connection = http.client.HTTPConnection(endpoint['host'], endpoint['port'], timeout=10)
try:
    connection.request('GET', '/')
    response = connection.getresponse()
    body = response.read()
    headers = dict(response.getheaders())
finally:
    connection.close()
assert response.status == 200 and headers['Server'].startswith('Apache/')
assert b'module-target-http-marker' in body
command = subprocess.run(runtime['compose'] + ['exec', '-T', 'target', 'cat', '/usr/local/apache2/htdocs/index.html'], capture_output=True, timeout=10, check=True)
assert body == command.stdout
command = subprocess.run(runtime['compose'] + ['exec', '-T', 'target', 'cat', '/proc/1/stat'], capture_output=True, timeout=10, check=True)
fields = command.stdout.decode().split()
result = {'status': 'native_passed', 'phase': phase, 'identity': {'pid': fields[0], 'starttime': fields[21], 'server': headers['Server']},
          'files': {'index': {'sha256': hashlib.sha256(body).hexdigest(), 'base64': base64.b64encode(body).decode()}}, 'http_status': response.status, 'headers': headers}
Path(runtime['artifacts'], 'native-' + phase + '.json').write_text(json.dumps(result, indent=2) + '\n')
print(json.dumps({'status': result['status']}))
