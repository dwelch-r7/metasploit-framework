"""Single-release endpoint adapter; reuse the sealed CLI/HTTP recorder methods."""
import json
from pathlib import Path
import sys

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / 'druid'))
from native_client import NativeDruid


class SingleDruid(NativeDruid):
    def __init__(self, runtime):
        self.runtime = runtime
        self.artifacts = Path(runtime['artifacts'])
        self.commands = []
        self.requests = []
        config = json.loads(self.compose('config', '--format', 'json')['stdout'])
        assert set(config['services']) == {'metadata', 'zookeeper', 'app', 'gateway', 'framework'}
        assert sum(int(item['mem_limit']) for item in config['services'].values()) <= 2208 * 1024 * 1024
        assert sum(float(item['cpus']) for item in config['services'].values()) <= 2.35
        network = config['networks']['default']['name']
        assert config['networks']['default']['internal'] is True
        self.endpoints = {}
        self.identities = {}
        for service in ['app', 'gateway', 'framework', 'metadata', 'zookeeper']:
            identifier = self.compose('ps', '--quiet', service)['stdout'].strip()
            details = json.loads(self.command(['docker', 'inspect', identifier])['stdout'])[0]
            selected = details['NetworkSettings']['Networks'][network]
            assert selected['IPAddress'] and selected['NetworkID']
            assert details['State']['Running'] and not details['State']['OOMKilled']
            assert details['State']['Health']['Status'] == 'healthy'
            definition = config['services'][service]
            assert details['HostConfig']['Memory'] == int(definition['mem_limit'])
            assert details['HostConfig']['NanoCpus'] == int(float(definition['cpus']) * 1_000_000_000)
            if service != 'framework':
                assert '@sha256:' in definition['image']
                assert details['Config']['Image'] == definition['image']
            self.identities[service] = {'id': details['Id'], 'image_id': details['Image'], 'requested_image': details['Config']['Image'], 'network': selected, 'limits': details['HostConfig']}
            self.endpoints[service] = {'host': selected['IPAddress'], 'port': 80 if service == 'gateway' else 8081}
            if service == 'framework':
                assert list(details['NetworkSettings']['Networks']) == [network]
                if runtime.get('listener_host'):
                    assert selected['IPAddress'] == runtime['listener_host']
        self.endpoints['unrelated'] = self.endpoints['gateway']
        binding = self.compose('port', 'gateway', '80')['stdout'].strip()
        assert binding.startswith('127.0.0.1:') and int(binding.rsplit(':', 1)[1]) > 0
        self.base_url = 'http://' + binding
        self.artifacts.joinpath('native-endpoints.json').write_text(json.dumps({'module_endpoints': self.endpoints, 'base_url': self.base_url, 'identities': self.identities}, indent=2))
