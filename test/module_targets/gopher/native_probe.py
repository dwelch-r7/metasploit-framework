"""Capture genuine Gopher/HTTP bytes and native fixture state independently."""
import base64
import hashlib
import http.client
import json
from pathlib import Path
import socket
import subprocess
import sys

runtime = json.loads(Path(sys.argv[1]).read_text())
phase = sys.argv[2]
commands, requests = [], []
result = {'phase': phase, 'status': 'starting', 'commands': commands, 'requests': requests}


def execute(service, *argv, expected=0, user=None):
    args = runtime['compose'] + ['exec', '-T']
    if user:
        args += ['--user', user]
    args += [service, *argv]
    proc = subprocess.run(args, capture_output=True, timeout=30)
    row = {'argv': args, 'exitstatus': proc.returncode,
           'stdout_base64': base64.b64encode(proc.stdout).decode(),
           'stderr_base64': base64.b64encode(proc.stderr).decode()}
    commands.append(row)
    assert proc.returncode == expected, row
    return proc.stdout


def wire(selector, port):
    request = selector.encode() + b'\r\n'
    data = b''
    with socket.create_connection(('127.0.0.1', port), timeout=5) as sock:
        sock.sendall(request)
        while True:
            part = sock.recv(65536)
            if not part:
                break
            data += part
            assert len(data) < 1024 * 1024
    requests.append({'selector': selector, 'request_base64': base64.b64encode(request).decode(),
                     'response_base64': base64.b64encode(data).decode(),
                     'response_sha256': hashlib.sha256(data).hexdigest()})
    return data


try:
    port = runtime['endpoints']['target']['port']
    responses = {}
    for selector in ['', '/dir', '/space dir', '/custom', '/empty', '/empty-map', '/large', '/missing']:
        raw = wire(selector, port)
        assert raw.endswith(b'.\r\n'), (selector, raw[-100:])
        rows = []
        for line in raw[:-3].split(b'\r\n'):
            if not line:
                continue
            fields = line.decode().split('\t')
            assert len(fields) == 4 and fields[0] and fields[3].isdigit(), fields
            rows.append({'type': fields[0][0], 'description': fields[0][1:],
                         'selector': fields[1], 'host': fields[2], 'port': int(fields[3])})
        responses[selector] = {'base64': base64.b64encode(raw).decode(),
                               'sha256': hashlib.sha256(raw).hexdigest(), 'text': raw.decode(), 'rows': rows}
    assert responses['/empty']['rows'] == responses['/empty-map']['rows'] == []
    assert len(responses['/large']['rows']) == 512 and len(responses['/large']['text']) > 32768
    assert responses['/missing']['rows'][0]['type'] == '3'
    assert responses['/custom']['rows'][0]['type'] == 'i'
    files = {}
    for path in sorted((Path(__file__).parent / 'files').rglob('*')):
        if path.is_file():
            relative = path.relative_to(Path(__file__).parent / 'files').as_posix()
            raw = execute('target', 'cat', '/public/' + relative)
            assert raw == path.read_bytes()
            files[relative] = {'sha256': hashlib.sha256(raw).hexdigest(), 'base64': base64.b64encode(raw).decode()}
    raw = wire('/text.txt', port)
    assert raw == base64.b64decode(files['text.txt']['base64'])
    # An ordinary bundled BusyBox HTTP daemon supplies an unrelated real service.
    execute('target', 'sh', '-c', 'test -f /tmp/module-target-http.pid && kill -0 "$(cat /tmp/module-target-http.pid)" || { httpd -f -p 8080 -h /public >/tmp/module-target-http.log 2>&1 & echo $! >/tmp/module-target-http.pid; }')
    http_port = int(subprocess.check_output(runtime['compose'] + ['port', 'target', '8080'], text=True).strip().rsplit(':', 1)[1])
    conn = http.client.HTTPConnection('127.0.0.1', http_port, timeout=5)
    conn.request('GET', '/text.txt')
    reply = conn.getresponse()
    body = reply.read()
    assert reply.status == 200 and body == raw
    result['http'] = {'status': reply.status, 'body_base64': base64.b64encode(body).decode(), 'headers': reply.getheaders()}
    conn.close()
    # Confirm exactly what this genuine HTTP daemon does with a Gopher selector.
    with socket.create_connection(('127.0.0.1', http_port), timeout=1) as sock:
        sock.sendall(b'\r\n')
        try:
            result['http_gopher_request'] = {'outcome': 'response', 'base64': base64.b64encode(sock.recv(65536)).decode()}
        except socket.timeout:
            result['http_gopher_request'] = {'outcome': 'timeout', 'seconds': 1}
    identity = {}
    for process in ['gopher', 'httpd']:
        pid = execute('target', 'cat', '/tmp/module-target-http.pid').decode().strip() if process == 'httpd' else execute('target', 'pidof', process).decode().strip()
        assert pid.isdigit(), pid
        stat = execute('target', 'cat', '/proc/' + pid + '/stat').decode().split()
        identity[process] = {'pid': pid, 'starttime': stat[21]}
    source = {}
    for name in ['main.go', 'server.go', 'gophermap.go', 'Dockerfile']:
        raw = execute('target', 'cat', '/go/src/gopher/' + name)
        source[name] = hashlib.sha256(raw).hexdigest()
    assert source == json.loads((Path(__file__).parent / 'vendor.json').read_text())['source_sha256']
    database = execute('reporting_db', 'psql', '-U', 'module_framework', '-d', 'module_targets', '-Atc', 'SELECT current_user, current_database(), version()').decode()
    assert 'module_framework|module_targets|PostgreSQL 16.' in database
    execute('reporting_db', 'env', 'PGPASSWORD=module-target-wrong-password', 'psql', '-h', '127.0.0.1', '-U', 'module_framework', '-d', 'module_targets', '-Atc', 'SELECT current_user', expected=2)
    assert b'password authentication failed' in base64.b64decode(commands[-1]['stderr_base64'])
    cgroups = {}
    for service in ['target', 'reporting_db']:
        text = execute(service, 'sh', '-c', 'cat /sys/fs/cgroup/memory.events; cat /sys/fs/cgroup/pids.events').decode()
        assert 'oom 0' in text and 'oom_kill 0' in text
        assert all(line == 'max 0' for line in text.splitlines() if line.startswith('max ')), text
        cgroups[service] = text
    console = runtime['console_command']
    owner = console[console.index('--user') + 1]
    uid, gid = owner.split(':')
    assert execute('framework', 'id', '-u', user=owner).decode().strip() == uid
    assert execute('framework', 'id', '-g', user=owner).decode().strip() == gid
    host = runtime['module_endpoints']['target']['host']
    ruby = 'require "socket"; begin; Socket.tcp(ARGV[0], 1, connect_timeout: 2).close; abort "Unexpected open target port"; rescue Errno::ECONNREFUSED; puts "NATIVE_REFUSED"; end'
    refused = execute('framework', 'ruby', '-e', ruby, host, user=uid + ':' + gid).decode()
    assert refused.strip() == 'NATIVE_REFUSED'
    result.update(status='native_passed', responses=responses, files=files, source_sha256=source,
                  identity=identity, cgroups=cgroups, database=database, refused_port={'host': host, 'port': 1, 'uid': uid, 'gid': gid})
finally:
    Path(runtime['artifacts'], 'native-' + phase + '.json').write_text(json.dumps(result, indent=2) + '\n')
print(json.dumps({'status': result['status'], 'phase': phase, 'requests': len(requests)}))
