"""Recorded vendor commands and real HTTP controls for the isolated YARN lab."""
import base64
import datetime
import json
from pathlib import Path
import subprocess
import time
import urllib.error
import urllib.request


class NativeHadoop:
    def __init__(self, runtime):
        self.runtime = runtime
        self.commands = []
        self.requests = []

    def command(self, service, *arguments, check=True, timeout=30):
        started = time.monotonic()
        started_at = datetime.datetime.now(datetime.timezone.utc).isoformat()
        proc = subprocess.run(self.runtime['compose'] + ['exec', '-T', service] + list(arguments), capture_output=True, timeout=timeout)
        row = dict(service=service, argv=list(arguments), exitstatus=proc.returncode,
                   stdout=proc.stdout.decode(errors='replace'), stderr=proc.stderr.decode(errors='replace'),
                   seconds=time.monotonic() - started, started_at=started_at)
        self.commands.append(row)
        if check:
            assert proc.returncode == 0, row
        return row

    def request(self, service, path, *, method='GET', data=None, auth=None):
        endpoint = self.runtime['endpoints'][service]
        assert endpoint['host'] == '127.0.0.1'
        url = f"http://127.0.0.1:{endpoint['port']}{path}"
        raw = json.dumps(data).encode() if data is not None else None
        headers = {'Accept': 'application/json', 'Content-Type': 'application/json'}
        if auth:
            headers['Authorization'] = 'Basic ' + base64.b64encode(':'.join(auth).encode()).decode()
        req = urllib.request.Request(url, data=raw, method=method, headers=headers)
        try:
            res = urllib.request.build_opener(urllib.request.ProxyHandler({})).open(req, timeout=10)
        except urllib.error.HTTPError as error:
            res = error
        body = res.read()
        self.requests.append(dict(service=service, url=url, method=method, request_body_base64=base64.b64encode(raw or b'').decode(),
                                  status=res.code, headers=dict(res.headers), body_base64=base64.b64encode(body).decode()))
        try:
            document = json.loads(body)
        except (ValueError, UnicodeDecodeError):
            document = None
        return res.code, document, body

    def wait(self, predicate, timeout=30):
        deadline = time.monotonic() + timeout
        while True:
            result = predicate()
            if result:
                return result
            assert time.monotonic() < deadline, 'Native condition exceeded its bounded wait'
            time.sleep(0.3)

    def idle(self):
        code, document, body = self.request('resourcemanager', '/ws/v1/cluster/metrics')
        assert code == 200, body
        metrics = document['clusterMetrics']
        return metrics['activeNodes'] == 1 and metrics['appsPending'] == 0 and metrics['appsRunning'] == 0 and metrics['containersAllocated'] == 0

    def kill(self, app):
        code, _, body = self.request('resourcemanager', f'/ws/v1/cluster/apps/{app}/state', method='PUT', data={'state': 'KILLED'})
        assert code in (200, 202), body
        def terminal():
            status, document, raw = self.request('resourcemanager', f'/ws/v1/cluster/apps/{app}')
            assert status == 200, raw
            return document['app']['state'] in ('KILLED', 'FINISHED', 'FAILED')
        self.wait(terminal)
        self.wait(self.idle)

    def marker(self, service, prefix, suffix, auth=None):
        path = '/tmp/module-target-hadoop-native-' + suffix
        self.command('nodemanager', 'test', '!', '-e', path)
        code, allocation, raw = self.request(service, prefix + 'ws/v1/cluster/apps/new-application', method='POST', auth=auth)
        assert code == 200, raw
        app = allocation['application-id']
        try:
            code, _, raw = self.request(service, prefix + 'ws/v1/cluster/apps', method='POST', auth=auth,
                                       data={'application-id': app, 'application-name': 'native-' + suffix, 'application-type': 'YARN',
                                             'am-container-spec': {'commands': {'command': "printf '%s' 'Native Hadoop: real command' > " + path}}})
            assert code == 202, raw
            def written():
                row = self.command('nodemanager', 'cat', path, check=False)
                return row['exitstatus'] == 0 and row['stdout'] == 'Native Hadoop: real command'
            self.wait(written)
            owner = self.command('nodemanager', 'stat', '-c', '%u:%g', path)['stdout'].strip()
            assert owner == '1000:100', owner
        finally:
            self.kill(app)
            self.command('nodemanager', 'rm', '-f', path)
            self.command('nodemanager', 'test', '!', '-e', path)
        return dict(application=app, path=path, owner=owner, exact_bytes='Native Hadoop: real command')

    def write(self, path, **extra):
        Path(path).write_text(json.dumps(dict(commands=self.commands, requests=self.requests, **extra), indent=2) + '\n')
