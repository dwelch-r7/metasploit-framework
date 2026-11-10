"""Real Docker CLI / HTTP observations; no Framework or simulated Druid API."""
import base64
import datetime
import json
import pathlib
import subprocess
import urllib.error
import urllib.request


class NativeDruid:
    def __init__(self, runtime):
        self.runtime = runtime
        self.artifacts = pathlib.Path(runtime['artifacts'])
        self.commands = []
        self.requests = []
        config = json.loads(self.compose('config', '--format', 'json')['stdout'])
        network = config['networks']['default']['name']
        assert config['networks']['default']['internal'] is True
        self.endpoints = {}
        self.identities = {}
        for service in ['vulnerable', 'fixed', 'gateway']:
            identifier = self.compose('ps', '--quiet', service)['stdout'].strip()
            inspected = self.command(['docker', 'inspect', identifier])
            details = json.loads(inspected['stdout'])[0]
            selected = details['NetworkSettings']['Networks'][network]
            assert selected['IPAddress'] and selected['NetworkID']
            self.identities[service] = {'id': details['Id'], 'image_id': details['Image'], 'network': selected}
            self.endpoints[service] = {'host': selected['IPAddress'], 'port': 80 if service == 'gateway' else 8081}
        self.endpoints['unrelated'] = self.endpoints['gateway']
        binding = self.compose('port', 'gateway', '80')['stdout'].strip()
        assert binding.startswith('127.0.0.1:') and int(binding.rsplit(':', 1)[1]) > 0, binding
        self.base_url = 'http://' + binding
        # Runner's ports:{} keeps the dual-network gateway out of its deliberate
        # single-network endpoint assumption. Framework remains internal only.
        if 'listener_host' in runtime:
            identifier = self.compose('ps', '--quiet', 'framework')['stdout'].strip()
            details = json.loads(self.command(['docker', 'inspect', identifier])['stdout'])[0]
            networks = details['NetworkSettings']['Networks']
            assert list(networks) == [network]
            assert networks[network]['IPAddress'] == runtime['listener_host']
            assert networks[network]['NetworkID'] == self.identities['vulnerable']['network']['NetworkID']
        self.artifacts.joinpath('native-endpoints.json').write_text(json.dumps({'module_endpoints': self.endpoints, 'base_url': self.base_url, 'identities': self.identities, 'listener_host': runtime.get('listener_host')}, indent=2))

    def command(self, argv, data=None, check=True):
        result = subprocess.run(argv, input=data, capture_output=True, timeout=40)
        row = {'argv': argv, 'exitstatus': result.returncode, 'stdout': result.stdout.decode(errors='replace'), 'stderr': result.stderr.decode(errors='replace')}
        if data is not None:
            row['stdin_base64'] = base64.b64encode(data).decode()
        self.commands.append(row)
        self.save()
        if check:
            assert result.returncode == 0, row
        return row

    def compose(self, *args, **kwargs):
        return self.command(self.runtime['compose'] + list(args), **kwargs)

    def cli(self, service, *args, **kwargs):
        return self.compose('exec', '-T', service, *args, **kwargs)

    def request(self, route, path, data=None, auth=None):
        raw = json.dumps(data).encode() if data is not None else None
        headers = {'Content-Type': 'application/json', 'Accept': 'application/json'}
        if auth is not None:
            headers['Authorization'] = 'Basic ' + base64.b64encode(':'.join(auth).encode()).decode()
        row = {'url': self.base_url + route + path, 'request_bytes_hex': raw.hex() if raw else '', 'request_headers': headers, 'started_at': datetime.datetime.now(datetime.timezone.utc).isoformat()}
        self.requests.append(row)
        try:
            request = urllib.request.Request(row['url'], data=raw, headers=headers)
            try:
                response = urllib.request.urlopen(request, timeout=12)
            except urllib.error.HTTPError as error:
                response = error
            row.update(status=response.code, headers=dict(response.headers), response=response.read().decode())
        except Exception as error:
            row.update(error=type(error).__name__, message=str(error))
            raise
        finally:
            self.save()
        return row

    def save(self):
        self.artifacts.joinpath('native-druid-observations.json').write_text(json.dumps({'commands': self.commands, 'requests': self.requests}, indent=2))
