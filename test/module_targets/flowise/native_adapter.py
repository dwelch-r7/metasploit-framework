"""Recorded real CLI/HTTP controls; no simulated Flowise or model responses."""
import base64
import datetime
import http.cookiejar
import json
from pathlib import Path
import sys
import urllib.error
import urllib.request

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / 'druid'))
from native_client import NativeDruid


class NativeFlowise(NativeDruid):
    def __init__(self, runtime, profile):
        self.runtime = runtime
        self.profile = profile
        self.artifacts = Path(runtime['artifacts'])
        self.commands = []
        self.requests = []
        self.observations_name = 'native-flowise-observations.json'
        self.definition = json.loads((Path(__file__).parent / 'profiles.json').read_text())[profile]
        self.config = json.loads(self.compose('config', '--format', 'json')['stdout'])
        expected = {'app', 'framework', 'gateway'}
        if self.definition['smtp']:
            expected.add('smtp')
        if self.definition['database']:
            expected.add('reporting_db')
        assert set(self.config['services']) == expected
        limits = {'app': (1024, 0.9), 'framework': (768, 1.0), 'gateway': (96, 0.1), 'smtp': (96, 0.1), 'reporting_db': (256, 0.15)}
        assert len(expected) <= 5
        network = self.config['networks']['default']['name']
        assert self.config['networks']['default']['internal'] is True
        self.endpoints = {}
        self.identities = {}
        for name in sorted(expected):
            identifier = self.compose('ps', '--quiet', name)['stdout'].strip()
            item = json.loads(self.command(['docker', 'inspect', identifier])['stdout'])[0]
            service = self.config['services'][name]
            memory, cpus = limits[name]
            assert int(service['mem_limit']) == memory * 1024 * 1024
            assert float(service['cpus']) == cpus
            assert item['HostConfig']['Memory'] == memory * 1024 * 1024
            assert item['HostConfig']['NanoCpus'] == int(cpus * 1_000_000_000)
            assert item['State']['Running'] and not item['State']['OOMKilled']
            assert item['State']['Health']['Status'] == 'healthy'
            address = item['NetworkSettings']['Networks'][network]['IPAddress']
            assert address
            cgroup = self.command(['docker', 'exec', identifier, 'sh', '-c', 'cat /sys/fs/cgroup/memory.max /sys/fs/cgroup/cpu.max /sys/fs/cgroup/memory.events'])['stdout'].splitlines()
            assert int(cgroup[0]) == memory * 1024 * 1024
            quota, period = map(int, cgroup[1].split())
            assert abs(quota / period - cpus) < 0.000001
            assert not any(line.startswith(('oom ', 'oom_kill ')) and int(line.split()[1]) for line in cgroup[2:])
            self.identities[name] = {'cgroup_v2': cgroup, 'id': item['Id'], 'image': item['Config']['Image'], 'image_id': item['Image'], 'address': address, 'memory_mib': memory, 'cpus': cpus}
            if name in ['app', 'gateway']:
                assert '@sha256:' in service['image'] and item['Config']['Image'] == service['image']
            if name == 'framework':
                assert list(item['NetworkSettings']['Networks']) == [network]
                assert address == runtime.get('listener_host', address)
        self.endpoints = {'app': {'host': self.identities['app']['address'], 'port': 3000}, 'gateway': {'host': self.identities['gateway']['address'], 'port': 80}}
        self.endpoints['unrelated'] = {'host': self.identities['gateway']['address'], 'port': 81}
        self.endpoints['missing'] = {'host': self.identities['gateway']['address'], 'port': 82}
        binding = self.compose('port', 'gateway', '80')['stdout'].strip()
        assert binding.startswith('127.0.0.1:') and int(binding.rsplit(':', 1)[1]) > 0
        self.base_url = 'http://' + binding
        self.artifacts.joinpath('native-endpoints.json').write_text(json.dumps({'module_endpoints': self.endpoints, 'identities': self.identities, 'base_url': self.base_url}, indent=2))

    @classmethod
    def attach(cls, runtime, profile, label):
        instance = cls.__new__(cls)
        instance.runtime = runtime
        instance.profile = profile
        instance.artifacts = Path(runtime['artifacts'])
        instance.definition = json.loads((Path(__file__).parent / 'profiles.json').read_text())[profile]
        endpoints = json.loads(instance.artifacts.joinpath('native-endpoints.json').read_text())
        instance.endpoints = endpoints['module_endpoints']
        instance.identities = endpoints['identities']
        instance.base_url = endpoints['base_url']
        instance.commands = []
        instance.requests = []
        instance.observations_name = 'native-control-' + label + '.json'
        return instance

    @staticmethod
    def client():
        return urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))

    def request(self, path, data=None, client=None, headers=None, method=None):
        raw = json.dumps(data).encode() if data is not None else None
        request = urllib.request.Request(self.base_url + path, data=raw, headers={'Content-Type': 'application/json', 'Accept': 'application/json', **(headers or {})}, method=method)
        row = {'url': request.full_url, 'method': request.get_method(), 'data_base64': base64.b64encode(raw).decode() if raw is not None else None, 'at': datetime.datetime.now(datetime.timezone.utc).isoformat()}
        self.requests.append(row)
        try:
            try:
                response = (client or self.client()).open(request, timeout=10)
            except urllib.error.HTTPError as error:
                response = error
            body = response.read()
            row.update(request_headers=dict(request.header_items()), status=response.code, response_headers=dict(response.headers), body_base64=base64.b64encode(body).decode())
            return response.code, body
        except (urllib.error.URLError, TimeoutError, OSError) as error:
            row.update(error=type(error).__name__, message=str(error))
            raise
        finally:
            self.save()

    def save(self):
        self.artifacts.joinpath(self.observations_name).write_text(json.dumps({'commands': self.commands, 'requests': self.requests}, indent=2))
