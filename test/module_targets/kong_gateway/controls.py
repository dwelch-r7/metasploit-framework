"""Reuse stock UID-100 shell/ELF/process controls with Kong's native backend."""
import importlib.util
import errno
import json
from pathlib import Path
import runpy
import socket
import sys

runtime, component, operation, *arguments = sys.argv[1:]
if component == 'host_port' and operation == 'refused':
    port = int(arguments[0])
    if not 0 < port < 65536:
        raise ValueError('Invalid loopback probe port')
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client:
        client.settimeout(1)
        result = client.connect_ex(('127.0.0.1', port))
    passed = result == errno.ECONNREFUSED
    data = {'host': '127.0.0.1', 'port': port, 'state': 'refused' if passed else 'open' if result == 0 else 'error',
            'errno': result, 'errno_name': errno.errorcode.get(result), 'independent_tcp_probe': True}
    print(json.dumps({'passed': passed, 'operation': 'host_port_refused', 'data': data,
                      'checks': [{'name': 'actual-loopback-connection-refused', 'passed': passed}], 'commands': []}))
    raise SystemExit(0 if passed else 1)

if component not in ['network.py', 'state_probe.py']:
    raise ValueError('Unknown stock-target control')

# The existing controls operate through the small native backend interface.
# Loading Kong's implementation keeps its database roles and evidence records;
# neither the shared controls nor the real Framework/target are replaced.
sys.argv = [sys.argv[0], runtime, operation, *arguments]
spec = importlib.util.spec_from_file_location('native', Path(__file__).with_name('native.py'))
backend = importlib.util.module_from_spec(spec)
sys.modules['native'] = backend
spec.loader.exec_module(backend)
sys.argv = [sys.argv[0], runtime, '2.1.4', operation, *arguments]
runpy.run_path(str(Path(__file__).parent.parent / 'kafka_ui' / component), run_name='__main__')
