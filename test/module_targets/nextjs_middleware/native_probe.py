"""Verify real Next.js middleware, vendor files and independent HTTP controls."""
import base64
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

runtime = json.loads(Path(sys.argv[1]).read_text())
profile, phase = sys.argv[2:4]
artifacts = Path(runtime['artifacts'])
configuration = json.loads((Path(__file__).parent / 'profiles.json').read_text())
commands, requests = [], []
result = {'status': 'starting', 'profile': profile, 'phase': phase, 'commands': commands, 'requests': requests}
base = 'http://{host}:{port}'.format(**runtime['endpoints']['target'])


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, file, code, message, headers, new_url):
        return None


client = urllib.request.build_opener(NoRedirect())


def execute(service, *argv, expected=0):
    process = subprocess.run(runtime['compose'] + ['exec', '-T', service, *argv], capture_output=True, timeout=60)
    record = {'service': service, 'argv': argv, 'exitstatus': process.returncode,
              'stdout_base64': base64.b64encode(process.stdout).decode(), 'stderr_base64': base64.b64encode(process.stderr).decode()}
    commands.append(record)
    assert process.returncode == expected, record
    return process.stdout


def request(path, headers=None):
    started = time.monotonic()
    try:
        response = client.open(urllib.request.Request(base + path, headers=headers or {}), timeout=20)
    except urllib.error.HTTPError as error:
        response = error
    with response:
        body = response.read()
        record = {'path': path, 'headers_sent': headers or {}, 'status': response.status,
                  'headers': dict(response.headers), 'body_base64': base64.b64encode(body).decode(),
                  'seconds': time.monotonic() - started}
    requests.append(record)
    return record, body


try:
    pg = ['psql', '-h', '127.0.0.1', '-U', 'module_framework', '-d', 'module_targets', '-v', 'ON_ERROR_STOP=1', '-Atc']
    result['postgres_version'] = execute('reporting_db', 'env', 'PGPASSWORD=module-target-framework-db-password', *pg, 'SELECT version()').decode().strip()
    assert not execute('reporting_db', 'env', 'PGPASSWORD=module-target-rejected-password', *pg, 'SELECT 1', expected=2)
    result['identity'] = execute('target', 'cat', '/proc/1/stat').decode().split(') ', 1)[1].split()[19]
    result['command_base64'] = base64.b64encode(execute('target', 'cat', '/proc/1/cmdline')).decode()
    ordinary, body = request('/')
    assert ordinary['status'] == 200
    result['ordinary_sha256'] = hashlib.sha256(body).hexdigest()
    if profile == 'unrelated':
        source = Path('test/module_targets/http')
        assert body == (source / 'htdocs/index.html').read_bytes()
        assert b'Apache/2.4.62' in execute('target', 'httpd', '-v')
        result['files'] = {}
        for relative, target in [('htdocs/index.html', '/usr/local/apache2/htdocs/index.html'),
                                 ('htdocs/protected/index.html', '/usr/local/apache2/htdocs/protected/index.html'),
                                 ('module-target.conf', '/usr/local/apache2/conf/extra/module-target.conf')]:
            digest = execute('target', 'sha256sum', target).decode().split()[0]
            assert digest == hashlib.sha256((source / relative).read_bytes()).hexdigest()
            result['files'][target] = digest
        assert request('/protected/')[0]['status'] == 401
        rejected = base64.b64encode(b'module-test-user:module-target-rejected-password').decode()
        assert request('/protected/', {'Authorization': 'Basic ' + rejected})[0]['status'] == 401
        accepted = base64.b64encode(b'module-test-user:module-test-password').decode()
        authenticated, protected = request('/protected/', {'Authorization': 'Basic ' + accepted})
        assert authenticated['status'] == 200 and protected == (source / 'htdocs/protected/index.html').read_bytes()
        for payload in [':'.join(['middleware'] * 5), ':'.join(['src/middleware'] * 5), 'middleware', 'src/middleware', 'pages/_middleware']:
            assert request('/protected/', {'x-middleware-subrequest': payload})[0]['status'] == 401
        assert request('/module-target-missing')[0]['status'] == 404
    else:
        selected = configuration['profiles'][profile]
        vendor = configuration['packages'][selected['version']]
        vulnerable = selected['version'] == '15.2.2'
        layout = selected['layout']
        assert b'PUBLIC MODULE TARGET' in body
        versions = json.loads(execute('target', 'node', '-p', "JSON.stringify({next:require('next/package.json').version,react:require('react/package.json').version,node:process.versions.node})"))
        assert versions == {'next': selected['version'], 'react': '19.0.0', 'node': '22.23.5'}
        result['versions'] = versions
        paths = list(vendor['vendor_files_sha256'])
        expected_files = dict(vendor['vendor_files_sha256'])
        source = Path(__file__).parent / 'application'
        prefix = '/srv/next/src' if layout == 'src' else '/srv/next'
        for path in sorted(source.rglob('*')):
            if not path.is_file():
                continue
            relative = str(path.relative_to(source))
            target = '/srv/next/next.config.js' if relative == 'next.config.js' else prefix + '/' + relative
            paths.append(target)
            expected_files[target] = hashlib.sha256(path.read_bytes()).hexdigest()
        result['files'] = {}
        for line in execute('target', 'sha256sum', *paths).decode().splitlines():
            digest, path = line.split('  ', 1)
            result['files'][path] = digest
        assert result['files'] == expected_files
        result['build_id'] = execute('target', 'cat', '/srv/next/.next/BUILD_ID').decode().strip()
        assert result['build_id']
        result['middleware_manifest'] = json.loads(execute('target', 'cat', '/srv/next/.next/server/middleware-manifest.json'))
        assert '/' in result['middleware_manifest']['middleware']
        own_name = 'src/middleware' if layout == 'src' else 'middleware'
        correct = ':'.join([own_name] * 5)
        payloads = [':'.join(['middleware'] * 5), ':'.join(['src/middleware'] * 5), 'middleware', 'src/middleware', 'pages/_middleware']
        result['payload_oracles'] = {}
        for payload in payloads:
            response, body = request('/dashboard', {'x-middleware-subrequest': payload})
            expected = 200 if vulnerable and payload == correct else 307
            assert response['status'] == expected, (payload, response)
            if expected == 200:
                assert b'PRIVATE MODULE TARGET DASHBOARD' in body
            else:
                assert response['headers']['x-module-target-gate'] == 'enforced'
            result['payload_oracles'][payload] = response['status']
        controls = {'/dashboard': (307, b'PRIVATE MODULE TARGET DASHBOARD'), '/api/protected': (401, b'PRIVATE MODULE TARGET API'),
                    '/forbidden': (403, b'PRIVATE MODULE TARGET AUTHORIZATION'), '/redirect302': (302, b'PRIVATE MODULE TARGET REDIRECT')}
        for path, (gate, marker) in controls.items():
            baseline, body = request(path)
            assert baseline['status'] == gate and marker not in body
            assert baseline['headers']['x-module-target-gate'] == 'enforced'
            if gate in (302, 307):
                location = next(value for name, value in baseline['headers'].items() if name.lower() == 'location')
                assert urllib.parse.urlparse(location).path == '/login'
            accepted, body = request(path, {'Cookie': 'session=module-target-next-session'})
            assert accepted['status'] == 200 and marker in body
            rejected, body = request(path, {'Cookie': 'session=module-target-rejected-session'})
            assert rejected['status'] == gate and marker not in body
            bypass, body = request(path, {'x-middleware-subrequest': correct})
            assert bypass['status'] == (200 if vulnerable else gate)
            assert (marker in body) == vulnerable
        assert request('/login')[0]['status'] == 200
        assert request('/module-target-missing')[0]['status'] == 404
        # Preserve the real normalization response without assuming middleware order.
        result['trailing_slash'] = [request('/dashboard/')[0], request('/dashboard/', {'x-middleware-subrequest': correct})[0]]
    protocol = configuration['protocol_rejection']
    rejection_payload = protocol['character'] * protocol['length']
    probe_path = protocol['apache_path'] if profile == 'unrelated' else protocol['nextjs_path']
    assert request(probe_path)[0]['status'] == 401
    rejected, body = request(probe_path, {'x-middleware-subrequest': rejection_payload})
    assert rejected['status'] in [400, 431]
    assert b'PRIVATE MODULE TARGET API' not in body
    if profile == 'unrelated':
        assert Path('test/module_targets/http/htdocs/protected/index.html').read_bytes() not in body
    result['protocol_rejection'] = {'response': rejected, 'payload_bytes': len(rejection_payload),
                                    'payload_sha256': hashlib.sha256(rejection_payload.encode()).hexdigest()}
    healthy, body = request('/')
    assert healthy['status'] == 200 and hashlib.sha256(body).hexdigest() == result['ordinary_sha256']
    assert request(probe_path)[0]['status'] == 401
    if profile != 'unrelated':
        baseline, body = request(protocol['downstream_path'])
        assert baseline['status'] == 307
        bypass, body = request(protocol['downstream_path'], {'x-middleware-subrequest': correct})
        assert bypass['status'] == (404 if vulnerable else 307)
        result['downstream_missing'] = {'baseline': baseline, 'probe': bypass}
        result['limits'] = execute('target', 'cat', '/sys/fs/cgroup/memory.events', '/sys/fs/cgroup/pids.events').decode()
        assert all(int(line.split()[1]) == 0 for line in result['limits'].splitlines())
    result['status'] = 'native_passed'
finally:
    (artifacts / ('native-' + phase + '.json')).write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({'status': result['status'], 'profile': profile, 'phase': phase, 'requests': len(requests)}))
