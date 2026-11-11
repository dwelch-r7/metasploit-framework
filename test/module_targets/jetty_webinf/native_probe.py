"""Independent HTTP/disk controls using the stock Jetty distribution and app."""
import base64
import hashlib
import http.client
import json
from pathlib import Path
import subprocess
import sys

runtime = json.loads(Path(sys.argv[1]).read_text())
profile = json.loads((Path(__file__).parent / 'profiles.json').read_text())[sys.argv[2]]
phase = sys.argv[3]
requests = []
commands = []


def execute(*argv, service='target'):
    completed = subprocess.run(runtime['compose'] + ['exec', '-T', service, *argv],
                               capture_output=True, timeout=20)
    commands.append({'service': service, 'argv': argv, 'exitstatus': completed.returncode,
                     'stdout_base64': base64.b64encode(completed.stdout).decode(),
                     'stderr_base64': base64.b64encode(completed.stderr).decode()})
    assert completed.returncode == 0, commands[-1]
    return completed.stdout


def request(path):
    endpoint = runtime['endpoints']['target']
    connection = http.client.HTTPConnection(endpoint['host'], endpoint['port'], timeout=10)
    try:
        connection.request('GET', path, headers={'Connection': 'close'})
        response = connection.getresponse()
        body = response.read()
        row = {'path': path, 'status': response.status, 'headers': dict(response.getheaders()),
               'body_base64': base64.b64encode(body).decode(), 'sha256': hashlib.sha256(body).hexdigest()}
        requests.append(row)
        return row, body
    finally:
        connection.close()


result = {'phase': phase, 'profile': sys.argv[2], 'requests': requests, 'commands': commands, 'status': 'starting'}
try:
    index = execute('cat', '/var/lib/jetty/webapps/ROOT/index.html')
    row, body = request('/')
    assert row['status'] == 200 and body == index == b'module-target-jetty-index\n'
    assert row['headers']['Server'] == 'Jetty(' + profile['server_version'] + ')', row
    uid = execute('id', '-u').decode().strip()
    assert uid != '0'
    # No second JVM is started. Read the actual server process start identity.
    script = 'for path in /proc/[0-9]*/comm; do if test "$(cat "$path" 2>/dev/null)" = java; then cat "${path%/comm}/stat"; fi; done'
    processes = execute('sh', '-c', script).decode().splitlines()
    assert len(processes) == 1, processes
    fields = processes[0].split()
    result['identity'] = {'uid': uid, 'pid': fields[0], 'starttime': fields[21], 'server_version': profile['server_version']}
    paths = ['web.xml', 'short.txt', 'empty.txt', 'unicode.txt', 'binary.dat', 'large.txt', 'classes/settings.properties']
    files = {name: execute('cat', '/var/lib/jetty/webapps/ROOT/WEB-INF/' + name) for name in paths}
    assert files['web.xml'] == (Path(__file__).parent / 'web.xml').read_bytes()
    assert files['unicode.txt'] == (Path(__file__).parent / 'unicode.txt').read_bytes()
    assert files['empty.txt'] == b'' and len(files['large.txt']) > 32768
    assert files['binary.dat'].startswith(b'\x00\xff')
    result['files'] = {name: {'base64': base64.b64encode(value).decode(), 'sha256': hashlib.sha256(value).hexdigest()} for name, value in files.items()}
    for name in paths:
        ordinary, body = request('/WEB-INF/' + name)
        assert ordinary['status'] in (403, 404) and body != files[name], ordinary
    for cve, prefix in [('CVE-2021-28164', '%2e'), ('CVE-2021-34429', '%u002e')]:
        for name in paths:
            response, body = request('/' + prefix + '/WEB-INF/' + name)
            if profile['vulnerable'][cve]:
                assert response['status'] == 200 and body == files[name], response
            else:
                assert response['status'] in (400, 403, 404), response
        missing, _body = request('/' + prefix + '/WEB-INF/module-target-missing.txt')
        assert missing['status'] in (400, 403, 404), missing
    # Probe the same target address from the same network namespace as the
    # module. A host-loopback port does not identify a container's closed port.
    host = runtime['module_endpoints']['target']['host']
    code = "begin; Socket.tcp(ARGV.fetch(0), 1, connect_timeout: 2) { raise 'Target port one is open' }; rescue Errno::ECONNREFUSED; puts 'REFUSED'; end"
    assert execute('ruby', '-rsocket', '-e', code, host, service='framework').strip() == b'REFUSED'
    result['port_one'] = {'service': 'framework', 'target_host': host, 'target_port': 1, 'result': 'refused'}
    result['status'] = 'native_passed'
finally:
    Path(runtime['artifacts'], 'native-' + phase + '.json').write_text(json.dumps(result, indent=2) + '\n')
print(json.dumps({'status': result['status'], 'requests': len(requests), 'files': len(result['files'])}))
