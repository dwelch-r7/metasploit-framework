"""Separate genuine profiler health from native command-substitution proof."""
import base64
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request
import psutil

root = Path(sys.argv[1])
nonce = sys.argv[2]
assert root.parent == Path('/tmp') and root.name.startswith('module-target-ray-jobs-')
origin = 'http://127.0.0.1:' + os.environ['MODULE_TARGET_RAY_HEAD_PORT']
requests = []
def request(path):
    try:
        response = urllib.request.urlopen(origin + path, timeout=25)
    except urllib.error.HTTPError as error:
        response = error
    with response:
        raw = response.read(2 * 1024 * 1024 + 1)
        assert len(raw) <= 2 * 1024 * 1024
        requests.append({'path': path, 'status': response.status, 'body_base64': base64.b64encode(raw).decode(), 'sha256': hashlib.sha256(raw).hexdigest()})
    return response.status, raw

status, raw = request('/nodes?view=summary')
assert status == 200
nodes = json.loads(raw)['data']['summary']
assert len(nodes) == 1
node = nodes[0]
pid = node['agent']['pid']
process = psutil.Process(pid)
assert process.uids().real == 1000
assert any(arg.endswith('/dashboard/agent.py') for arg in process.cmdline())
result = {'node': node, 'pid': pid, 'uid': process.uids().real, 'py_spy': shutil.which('py-spy'), 'requests': requests}
if result['py_spy']:
    binary = Path(result['py_spy'])
    result['py_spy_sha256'] = hashlib.sha256(binary.read_bytes()).hexdigest()
    version = subprocess.run([str(binary), '--version'], capture_output=True, text=True, timeout=10)
    result['py_spy_version'] = {'exitstatus': version.returncode, 'stdout': version.stdout, 'stderr': version.stderr}
query = {'pid': pid, 'ip': node['ip'], 'duration': 1, 'native': 0, 'format': 'flamegraph'}
status, raw = request('/worker/cpu_profile?' + urllib.parse.urlencode(query))
result['ordinary_profile'] = {'status': status, 'svg': b'<svg' in raw}
assert (status == 200 and result['ordinary_profile']['svg']) or (status == 500 and any(token in raw.lower() for token in [b'permission', b'py-spy', b'operation not permitted'])), requests[-1]
marker = root / ('native-profiler-' + nonce)
assert not marker.exists()
query['format'] = '`printf ' + nonce + ' > ' + str(marker) + '`'
request('/worker/cpu_profile?' + urllib.parse.urlencode(query))
assert marker.read_text() == nonce and marker.stat().st_uid == 1000
result['exact_native_command_marker'] = True
marker.unlink()
print('MODULE_TARGET_PROFILER_JSON:' + json.dumps(result))
