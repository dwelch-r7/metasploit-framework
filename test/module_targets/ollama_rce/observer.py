"""Resident evidence/fixture recovery; never exec a process while preload is armed."""
from pathlib import Path
import base64
import hashlib
import http.server
import json
import os
import signal
import socket
import subprocess
import threading
import urllib.parse

ROOT = Path('/tmp/module-target-ollama')
PROOF = Path('/tmp/module-target-ollama-native-proof')
PRELOAD = Path('/etc/ld.so.preload')
ROOT.mkdir()
(ROOT / 'native').mkdir()
(ROOT / 'owner').mkdir()
assert not PRELOAD.exists()
backend = subprocess.Popen(['/bin/ollama', 'serve'])
callback_host = socket.gethostbyname('host.docker.internal')
vendor_hashes = {}
for line in Path('/vendor.sha256').read_text().splitlines():
    digest, name = line.split(maxsplit=1)
    assert hashlib.sha256(Path(name).read_bytes()).hexdigest() == digest
    vendor_hashes[name] = digest


def controlled(value):
    path = Path(value)
    if path in (PROOF, PRELOAD):
        return path
    assert path.is_absolute() and '..' not in path.parts and path.is_relative_to(ROOT), value
    assert not path.is_symlink(), value
    return path


def file(value):
    path = controlled(value)
    if not path.exists():
        return dict(exists=False)
    assert path.is_file()
    content = path.read_bytes()
    return dict(exists=True, uid=path.stat().st_uid, bytes=len(content), sha256=hashlib.sha256(content).hexdigest(),
                base64=base64.b64encode(content).decode())


def process_state():
    connections = []
    for table in ('tcp', 'tcp6'):
        for line in (Path('/proc/net') / table).read_text().splitlines()[1:]:
            fields = line.split()
            if int(fields[2].rsplit(':', 1)[1], 16) == 4492 and fields[3] != '06':
                connections.append(dict(table=table, local=fields[1], remote=fields[2], state=fields[3], inode=fields[9]))
    wanted = {row['inode'] for row in connections}
    processes = []
    for path in Path('/proc').iterdir():
        if not path.name.isdecimal():
            continue
        try:
            raw = (path / 'stat').read_text().rsplit(') ', 1)[1].split()
            command = (path / 'cmdline').read_bytes().replace(b'\0', b' ').decode(errors='replace').strip()
            uid = (path / 'status').read_text().split('Uid:', 1)[1].split()[0]
            sockets = []
            for descriptor in (path / 'fd').iterdir():
                try:
                    link = descriptor.readlink().as_posix()
                except FileNotFoundError:
                    continue
                if link.startswith('socket:[') and link[8:-1] in wanted:
                    sockets.append(link[8:-1])
            processes.append(dict(pid=int(path.name), ppid=int(raw[1]), birth=raw[19], state=raw[0], uid=uid,
                                  command=command, connection_inodes=sorted(sockets)))
        except (FileNotFoundError, ProcessLookupError):
            continue
    return dict(processes=sorted(processes, key=lambda row: row['pid']), connections=connections)


class Observer(http.server.BaseHTTPRequestHandler):
    def log_message(self, *arguments):
        pass

    def do_GET(self):
        request = urllib.parse.urlsplit(self.path)
        if request.path == '/snapshot':
            value = dict(observer_pid=os.getpid(), backend_pid=backend.pid, backend_exit=backend.poll(),
                         uid=os.getuid(), preload=file(str(PRELOAD)), proof=file(str(PROOF)), state=process_state(),
                         resources={name: dict(line.split() for line in (Path('/sys/fs/cgroup') / name).read_text().splitlines())
                                    for name in ('memory.events', 'pids.events')},
                         files=sorted(str(path) for path in ROOT.rglob('*') if path.is_file()))
        elif request.path == '/file':
            value = file(urllib.parse.parse_qs(request.query)['path'][0])
        elif request.path == '/metadata':
            native = Path('/opt/module-target/native-loader.so').read_bytes()
            value = dict(vendor_sha256={name: hashlib.sha256(Path(name).read_bytes()).hexdigest() for name in vendor_hashes}, native_base64=base64.b64encode(native).decode(),
                         callback_host=callback_host,
                         compiler=Path('/opt/module-target/native-compiler.txt').read_text(),
                         os_release=Path('/etc/os-release').read_text(), uid=os.getuid())
        else:
            self.send_error(404)
            return
        self.respond(value)

    def do_POST(self):
        data = json.loads(self.rfile.read(int(self.headers.get('Content-Length', 0))) or b'{}')
        if self.path == '/local-loader':
            assert not PRELOAD.exists() and not PROOF.exists()
            result = subprocess.run(['/usr/bin/true'], env=dict(os.environ, LD_PRELOAD='/opt/module-target/native-loader.so'), capture_output=True, timeout=5)
            value = dict(exit=result.returncode, stdout=base64.b64encode(result.stdout).decode(),
                         stderr=base64.b64encode(result.stderr).decode(), proof=file(str(PROOF)))
        elif self.path == '/remove':
            removed = []
            for value in data['paths']:
                path = controlled(value)
                if path == PRELOAD and path.exists():
                    assert path.read_text().strip().startswith(str(ROOT) + '/')
                if path.exists():
                    assert path.is_file() and not path.is_symlink()
                    path.unlink()
                    removed.append(str(path))
            value = dict(removed=removed)
        else:
            self.send_error(404)
            return
        self.respond(value)

    def respond(self, value):
        content = json.dumps(value).encode()
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(content)))
        self.end_headers()
        self.wfile.write(content)


server = http.server.ThreadingHTTPServer(('0.0.0.0', 11435), Observer)


def stop(number, frame):
    threading.Thread(target=server.shutdown, daemon=True).start()


signal.signal(signal.SIGTERM, stop)
signal.signal(signal.SIGINT, stop)
try:
    server.serve_forever()
finally:
    server.server_close()
    backend.terminate()
    try:
        backend.wait(timeout=10)
    except subprocess.TimeoutExpired:
        backend.kill()
        backend.wait(timeout=5)
