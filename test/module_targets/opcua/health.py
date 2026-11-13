import socket
import subprocess

for port in [4840, 4841]:
    result = subprocess.run(['/opt/opcua-bin/opcua-lab-client', f'opc.tcp://127.0.0.1:{port}'], capture_output=True, text=True, timeout=8)
    assert result.returncode == 0 and 'OPCUA_NATIVE_VERSION=1.5.10' in result.stdout, result.stdout + result.stderr
with socket.create_connection(('127.0.0.1', 2525), timeout=2) as connection:
    assert connection.recv(4096).startswith(b'220 ')
