"""Real Bash TCP, netcat and FIFO prerequisites in the isolated target."""
import json
import os
from pathlib import Path
import sys

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / 'druid'))
from native_client import NativeDruid

runtime = json.loads(Path(os.environ['MODULE_TARGET_RUNTIME']).read_text())
phase = Path(runtime['artifacts']) / 'native-runtime-tools'
phase.mkdir()
client = NativeDruid(dict(runtime, artifacts=str(phase)))
http = b'GET / HTTP/1.0\r\nHost: module-target-druid\r\nConnection: close\r\n\r\n'
try:
    response = client.cli('vulnerable', 'nc', '-w', '3', 'gateway', '80', data=http)['stdout']
    assert response.startswith('HTTP/1.1 200 OK\r\n'), response
    code = "exec 3<>/dev/tcp/gateway/80; printf 'GET / HTTP/1.0\\r\\nHost: module-target-druid\\r\\nConnection: close\\r\\n\\r\\n' >&3; IFS= read -r line <&3; printf '%s' \"$line\""
    response = client.cli('vulnerable', 'bash', '-c', code)['stdout']
    assert response == 'HTTP/1.1 200 OK\r', response
    fifo = '/tmp/module-target-druid-native-fifo'
    client.cli('vulnerable', 'test', '!', '-e', fifo)
    client.cli('vulnerable', 'mkfifo', fifo)
    info = client.cli('vulnerable', 'stat', '-c', '%u:%g:%F', fifo)['stdout'].strip()
    assert info == '1000:1000:fifo', info
    client.cli('vulnerable', 'rm', '--', fifo)
    client.cli('vulnerable', 'test', '!', '-e', fifo)
    client.cli('vulnerable', 'test', '-x', '/bin/touch')
    proof = {'netcat_native_http': True, 'bash_dev_tcp_native_http': True, 'fifo_uid_gid_type': info, 'fifo_removed': True, 'touch_executable': True, 'counts': {'commands': len(client.commands), 'requests': len(client.requests)}}
    phase.joinpath('proof.json').write_text(json.dumps(proof, indent=2))
    print(json.dumps(proof))
finally:
    client.save()
