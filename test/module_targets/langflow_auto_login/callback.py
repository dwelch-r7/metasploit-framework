"""Calibrate the existing Langflow verifier's callback port and real target UID."""
import importlib.util
import json
import socket
import threading

spec = importlib.util.spec_from_file_location('langflow_native', 'test/module_targets/langflow/native.py')
backend = importlib.util.module_from_spec(spec)
spec.loader.exec_module(backend)
native = backend.Native('auto-login-callback')
host = native.execute('python', '-c', 'import socket;print(socket.gethostbyname("host.docker.internal"))').decode().strip()
record = {'host': host, 'bind': '0.0.0.0', 'port': 4492}
server = socket.socket()
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server.bind((record['bind'], record['port']))
server.listen(1)
server.settimeout(10)


def receive():
    try:
        with server.accept()[0] as peer:
            peer.settimeout(10)
            with peer.makefile('rb') as stream:
                record['peer'] = json.loads(stream.readline())
                peer.sendall(b'langflow-native-ack\n')
                record['eof'] = stream.read(1) == b''
    except Exception as error:
        record['error'] = {'type': type(error).__name__, 'message': str(error)}


thread = threading.Thread(target=receive, daemon=True)
thread.start()
try:
    program = 'import socket,os,json,sys;peer=socket.create_connection((sys.argv[1],int(sys.argv[2])),timeout=10);peer.sendall((json.dumps(dict(uid=os.getuid(),pid=os.getpid(),token="langflow-native"))+"\\n").encode());answer=peer.makefile("rb").readline();assert answer==b"langflow-native-ack\\n";peer.close()'
    native.execute('python', '-c', program, host, str(record['port']))
    thread.join(2)
    assert not thread.is_alive() and 'error' not in record and record.get('eof')
    assert record['peer']['uid'] == 1000 and record['peer']['token'] == 'langflow-native'
    native.execute('test', '!', '-e', '/proc/' + str(record['peer']['pid']))
    record['passed'] = True
finally:
    server.close()
    thread.join(12)
    (native.artifacts / 'langflow-auto-callback.json').write_text(json.dumps(record, indent=2) + '\n')
    print(json.dumps(record))
