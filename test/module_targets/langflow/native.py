"""Native application/API/SDK controls, independent of the Framework owner."""
from pathlib import Path
import base64
import gzip
import hashlib
import json
import os
import re
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request


class Native:
    def __init__(self, tag):
        self.runtime = json.loads(Path(os.environ['MODULE_TARGET_RUNTIME']).read_text())
        self.profile = os.environ['LANGFLOW_PROFILE']
        self.protected = self.profile == 'auth'
        self.artifacts = Path(self.runtime['artifacts'])
        self.state_path = self.artifacts / 'langflow-native-state.json'
        self.tag = tag
        self.journal = []
        self.port = self.command('port', 'target', '7860').decode().strip().rsplit(':', 1)[1]

    def save(self):
        (self.artifacts / ('native-' + self.tag + '.json')).write_text(json.dumps(self.journal, indent=2) + '\n')

    def command(self, *arguments):
        argv = self.runtime['compose'] + list(arguments)
        result = subprocess.run(argv, capture_output=True, timeout=45)
        self.journal.append(dict(argv=argv, actual_exit=result.returncode,
                                 stdout_base64=base64.b64encode(result.stdout).decode(),
                                 stderr_base64=base64.b64encode(result.stderr).decode()))
        self.save()
        if result.returncode:
            raise RuntimeError(result.stderr.decode(errors='replace'))
        return result.stdout

    def execute(self, *arguments):
        return self.command('exec', '-T', 'target', *arguments)

    def http(self, path, token=None, data=None, method=None, form=None, timeout=10):
        headers = {}
        encoded = None
        if data is not None:
            encoded = json.dumps(data, ensure_ascii=False).encode()
            headers['Content-Type'] = 'application/json'
        if form is not None:
            encoded = urllib.parse.urlencode(form).encode()
            headers['Content-Type'] = 'application/x-www-form-urlencoded'
        if token:
            headers['Authorization'] = 'Bearer ' + token
        request = urllib.request.Request('http://127.0.0.1:' + self.port + path,
                                         headers=headers, data=encoded, method=method)
        try:
            response = urllib.request.urlopen(request, timeout=timeout)
        except urllib.error.HTTPError as error:
            response = error
        # A successful SSE stream has no finite body; inspect only its headers.
        raw = b'' if response.headers.get('Content-Type', '').startswith('text/event-stream') else response.read()
        response.close()
        decoded = gzip.decompress(raw) if raw.startswith(b'\x1f\x8b') or response.headers.get('Content-Encoding', '').lower() == 'gzip' else raw
        self.journal.append(dict(path=path, method=method or ('POST' if encoded is not None else 'GET'),
                                 data=data, form=form, authenticated=bool(token), status=response.status,
                                 headers=dict(response.headers), body_base64=base64.b64encode(raw).decode(),
                                 decoded_base64=base64.b64encode(decoded).decode()))
        self.save()
        return response.status, decoded

    def token(self):
        if self.protected:
            status, body = self.http('/api/v1/auto_login')
            assert status == 403
            status, body = self.http('/api/v1/login', form={
                'username': 'module-target-admin', 'password': 'module-target-native-password'})
        else:
            status, body = self.http('/api/v1/auto_login')
        assert status == 200
        token = json.loads(body)['access_token']
        assert token
        return token

    def flows(self, token):
        status, body = self.http('/api/v1/flows/', token)
        assert status == 200
        rows = json.loads(body)
        assert isinstance(rows, list)
        return rows

    def seed(self):
        assert not self.state_path.exists()
        token = self.token()
        baseline = sorted(row['id'] for row in self.flows(token))
        created = []
        if self.profile != 'empty':
            for name, description in [
                ('Module Native Alpha', 'Native information canary café 🧪'),
                ('Module Native Beta', 'Native long description ' + ('canary-data ' * 650))
            ]:
                status, body = self.http('/api/v1/flows/', token, data={
                    'name': name, 'description': description, 'data': {'nodes': [], 'edges': []},
                    'mcp_enabled': False, 'access_type': 'PRIVATE'})
                assert status == 201, (status, body)
                row = json.loads(body)
                assert row['user_id'] and row['mcp_enabled'] is False and row['access_type'] == 'PRIVATE'
                created.append(dict(id=row['id'], name=name, description=description))
        self.state_path.write_text(json.dumps(dict(baseline_ids=baseline, created=created), indent=2) + '\n')
        return self.verify()

    def vendor(self):
        program = """import importlib.metadata as m,importlib.util as u,pathlib,hashlib,json,os,sys
out={'uid':os.getuid(),'gid':os.getgid(),'python':sys.version.split()[0],'versions':{n:m.version(n) for n in ['langflow','langflow-base','lfx','mcp']},'sources':{}}
for package,relative in [('langflow','api/v1/mcp.py'),('langflow','services/auth/service.py'),('lfx','services/settings/auth.py')]:
 root=pathlib.Path(next(iter(u.find_spec(package).submodule_search_locations)));out['sources'][package+'/'+relative]=hashlib.sha256((root/relative).read_bytes()).hexdigest()
print(json.dumps(out))"""
        observed = json.loads(self.execute('python', '-c', program))
        expected = json.loads(Path(__file__).with_name('vendor.json').read_text())['installed']
        assert observed == expected, observed
        return observed

    def verify(self):
        state = json.loads(self.state_path.read_text())
        vendor = self.vendor()
        status, body = self.http('/api/v1/version')
        assert status == 200 and json.loads(body)['version'] == '1.8.4'
        assert self.http('/api/v1/flows/')[0] == 403
        if self.protected:
            assert self.http('/api/v1/mcp/sse')[0] == 403
        token = self.token()
        rows = self.flows(token)
        assert sorted(row['id'] for row in rows) == sorted(state['baseline_ids'] + [row['id'] for row in state['created']])
        for created in state['created']:
            flow = next(row for row in rows if row['id'] == created['id'])
            assert flow['name'] == created['name'] and flow['description'] == created['description']
            assert flow['mcp_enabled'] is False and flow['access_type'] == 'PRIVATE'
        arguments = ['exec', '-T']
        if self.protected:
            arguments += ['--env', 'MODULE_TARGET_CONTROL_TOKEN=' + token]
        sdk = json.loads(self.command(*arguments, 'target', 'python', '/opt/module-target-native.py'))
        assert sdk['initialize']['protocolVersion'] == '2025-06-18'
        assert sdk['initialize']['serverInfo'] == {'name': 'langflow-mcp-server', 'version': '1.26.0'}
        tools = sdk['tools']['tools']
        assert len(tools) == len(state['created'])
        for created in state['created']:
            assert any(tool['description'] == created['id'] + ': ' + created['description'] for tool in tools)
        return dict(vendor=vendor, flow_ids=sorted(row['id'] for row in rows), sdk=sdk,
                    protected=self.protected, anonymous_rest_status=403)

    def cleanup(self):
        state = json.loads(self.state_path.read_text())
        token = self.token()
        for flow in state['created']:
            assert self.http('/api/v1/flows/' + flow['id'], token, method='DELETE')[0] == 200
        assert sorted(row['id'] for row in self.flows(token)) == state['baseline_ids']
        return dict(flow_registry_restored=True)


if __name__ == '__main__':
    action, tag = sys.argv[1:]
    if action not in ('seed', 'verify', 'cleanup') or not re.fullmatch(r'[a-z0-9_-]+', tag):
        raise ValueError('Invalid native control')
    print(json.dumps(getattr(Native(tag), action)()))
