"""Native Ray prerequisites with raw literal HTTP paths and installed SDK jobs."""
import base64
import hashlib
import http.client
import json
from pathlib import Path
import subprocess
import sys
import traceback
import urllib.parse
import uuid


class NativeRay:
    def __init__(self, runtime):
        self.runtime = runtime
        self.commands = []
        self.requests = []

    def target(self, action, **options):
        source = Path(__file__).with_name('native_target.py').read_text()
        argv = self.runtime['compose'] + ['exec', '-T', 'ray', 'python', '-c', source, json.dumps(dict(action=action, **options))]
        row = {'argv': argv}
        self.commands.append(row)
        result = subprocess.run(argv, capture_output=True, text=True, timeout=210 if action == 'jobs' else 90)
        row.update(stdout=result.stdout, stderr=result.stderr, exitstatus=result.returncode)
        assert result.returncode == 0, row
        lines = [line.split(':', 1)[1] for line in result.stdout.splitlines() if line.startswith('MODULE_TARGET_RAY_JSON:')]
        assert len(lines) == 1, row
        return json.loads(lines[0])

    def request(self, service, path, data=None):
        origin = urllib.parse.urlsplit(self.runtime['endpoints'][service])
        assert origin.scheme == 'http' and origin.hostname == '127.0.0.1' and origin.port
        assert path.startswith('/') and not path.startswith('//')
        body = json.dumps(data).encode() if data is not None else None
        headers = {'Accept': 'application/json'}
        if data is not None:
            headers['Content-Type'] = 'application/json'
        row = {'endpoint': service, 'path': path, 'method': 'POST' if data is not None else 'GET', 'request_data': data}
        self.requests.append(row)
        connection = http.client.HTTPConnection(origin.hostname, origin.port, timeout=15)
        try:
            # http.client preserves literal ../ segments; a normalizing proxy
            # or URL convenience client would invalidate this native control.
            connection.request(row['method'], path, body=body, headers=headers)
            response = connection.getresponse()
            raw = response.read()
            row.update(status=response.status, headers=response.getheaders(), body_base64=base64.b64encode(raw).decode())
            return response.status, raw
        finally:
            connection.close()


def main():
    runtime = json.loads(Path(sys.argv[1]).read_text())
    artifacts = Path(runtime['artifacts'])
    native = NativeRay(runtime)
    result = {'status': 'native_failed', 'framework_calls': 0, 'owned_state_restored': False,
              'scope': ['installed identity', 'real native core task', 'native SDK jobs', 'static file read'],
              'not_qualified': ['owner modules', 'CPU profiling/injection', 'log traversal/enumeration', 'payloads/sessions']}
    try:
        manifest = runtime['source_manifest']
        identity = native.target('identity', files=list(manifest['files']))
        result['identity'] = identity
        assert identity['version'] == manifest['version'] and identity['commit'] == manifest['commit']
        assert identity['uid'] == 1000 and identity['static_build_exists']
        for name, expected in manifest['files'].items():
            actual = identity['sources'][name]
            assert actual['sha256'] == expected['sha256'], (name, actual['sha256'], expected)
            assert hashlib.sha256(base64.b64decode(actual['bytes_base64'])).hexdigest() == expected['sha256']
        nonce = uuid.uuid4().hex
        result['core'] = native.target('core', nonce=nonce)
        for name in ['gcs_server', 'raylet', 'dashboard/agent.py', 'dashboard/dashboard.py']:
            assert any(row['role'] == name and row['uid'] == 1000 for row in result['core']['processes']), name
        status, body = native.request('head', '/api/version')
        assert status == 200 and json.loads(body)['ray_version'] == manifest['version']
        status, _ = native.request('unrelated', '/api/version')
        assert status == 404
        result['fixtures'] = native.target('seed', nonce=nonce)
        fixture = result['fixtures']
        assert fixture['uid'] == 1000
        expected = base64.b64decode(fixture['content_base64'])
        controls = []
        for name in ['utf8', 'reserved', 'empty', 'missing']:
            raw_path = '/static/js/' + '../' * 16 + fixture['paths'][name].lstrip('/')
            path = urllib.parse.quote(raw_path, safe='/')
            status, content = native.request('head', path)
            if name == 'missing':
                assert status == 404, native.requests[-1]
            else:
                assert status == 200 and content == (b'' if name == 'empty' else expected), native.requests[-1]
            controls.append({'name': name, 'path': path, 'status': status, 'exact': name != 'missing'})
        result['static_file_controls'] = controls
        # Preserve genuine API discovery for later profiles; these observations
        # do not substitute for log traversal or profiler native prerequisites.
        for path in ['/api/cluster_status', '/nodes?view=summary', '/api/v0/logs?glob=*']:
            native.request('head', path)
        native.request('agent', '/api/jobs/')
        result['jobs'] = native.target('jobs', nonce=nonce, root=fixture['root'])
        cleanup = native.target('cleanup', nonce=nonce, root=fixture['root'], log=fixture['log'])
        assert cleanup['owned_fixture_paths_absent'] and result['jobs']['owned_submission_metadata_and_files_removed']
        result['owned_state_restored'] = True
        result['status'] = 'native_passed'
    except BaseException as error:
        result['failure'] = {'type': type(error).__name__, 'message': str(error), 'traceback': traceback.format_exc()}
        raise
    finally:
        (artifacts / 'native-observations.json').write_text(json.dumps({'commands': native.commands, 'requests': native.requests}, indent=2) + '\n')
        (artifacts / 'native-result.json').write_text(json.dumps(result, indent=2) + '\n')


if __name__ == '__main__':
    main()
