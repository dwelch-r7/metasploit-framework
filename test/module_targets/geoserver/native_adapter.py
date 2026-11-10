"""GeoServer discovery/HTTP; reuse the existing recorded Docker CLI methods."""
import base64
import datetime
import json
from pathlib import Path
import sys
import urllib.error
import urllib.request

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / 'druid'))
from native_client import NativeDruid


class NativeGeoServer(NativeDruid):
    def __init__(self, runtime):
        self.runtime = runtime
        self.artifacts = Path(runtime['artifacts'])
        self.commands = []
        self.requests = []
        config = json.loads(self.compose('config', '--format', 'json')['stdout'])
        assert set(config['services']) == {'app', 'gateway', 'framework'}
        assert sum(int(v['mem_limit']) for v in config['services'].values()) <= 1888 * 1024 * 1024
        assert sum(float(v['cpus']) for v in config['services'].values()) <= 2.0
        assert config['networks']['default']['internal'] is True
        network = config['networks']['default']['name']
        self.endpoints = {}
        self.identities = {}
        for name in ['app', 'gateway', 'framework']:
            identifier = self.compose('ps', '--quiet', name)['stdout'].strip()
            item = json.loads(self.command(['docker', 'inspect', identifier])['stdout'])[0]
            selected = item['NetworkSettings']['Networks'][network]
            assert item['State']['Running'] and not item['State']['OOMKilled']
            assert item['State']['Health']['Status'] == 'healthy'
            definition = config['services'][name]
            assert item['HostConfig']['Memory'] == int(definition['mem_limit'])
            assert item['HostConfig']['NanoCpus'] == int(float(definition['cpus']) * 1_000_000_000)
            if name != 'framework':
                assert '@sha256:' in definition['image']
                assert item['Config']['Image'] == definition['image']
            self.identities[name] = {'id': item['Id'], 'image_id': item['Image'], 'requested_image': item['Config']['Image'], 'network': selected}
            self.endpoints[name] = {'host': selected['IPAddress'], 'port': 80 if name == 'gateway' else 8080}
            assert selected['IPAddress']
            if name == 'framework':
                assert list(item['NetworkSettings']['Networks']) == [network]
                assert selected['IPAddress'] == runtime.get('listener_host', selected['IPAddress'])
        self.endpoints['unrelated'] = self.endpoints['gateway']
        binding = self.compose('port', 'gateway', '80')['stdout'].strip()
        assert binding.startswith('127.0.0.1:') and int(binding.rsplit(':', 1)[1]) > 0
        self.base_url = 'http://' + binding
        self.artifacts.joinpath('native-endpoints.json').write_text(json.dumps({'module_endpoints': self.endpoints, 'identities': self.identities, 'base_url': self.base_url}, indent=2))

    def request(self, path, data=None, auth=None, method=None, content_type='application/xml'):
        headers = {'Content-Type': content_type}
        if auth:
            headers['Authorization'] = 'Basic ' + base64.b64encode(':'.join(auth).encode()).decode()
        row = {'url': self.base_url + path, 'method': method or ('POST' if data is not None else 'GET'), 'headers': headers, 'data_base64': base64.b64encode(data).decode() if data is not None else None, 'at': datetime.datetime.now(datetime.timezone.utc).isoformat()}
        self.requests.append(row)
        try:
            request = urllib.request.Request(row['url'], data=data, headers=headers, method=row['method'])
            try:
                response = urllib.request.urlopen(request, timeout=10)
            except urllib.error.HTTPError as error:
                response = error
            body = response.read()
            row.update(status=response.code, response_headers=dict(response.headers), body_base64=base64.b64encode(body).decode())
            return response.code, body
        except (urllib.error.URLError, TimeoutError, OSError) as error:
            row.update(error=type(error).__name__, message=str(error))
            raise
        finally:
            self.save()

    def save(self):
        self.artifacts.joinpath('native-geoserver-observations.json').write_text(json.dumps({'commands': self.commands, 'requests': self.requests}, indent=2))
