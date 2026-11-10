"""Independent genuine Spark CLI and HTTP controls for the disposable lab."""
import base64
import http.client
import json
import os
import pathlib
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request


class SparkTarget:
    def __init__(self):
        self.runtime = json.loads(pathlib.Path(os.environ['MODULE_TARGET_RUNTIME']).read_text())
        self.directory = pathlib.Path(self.runtime['artifacts'])
        self.compose = self.runtime['compose']
        self.commands = []
        self.requests = []

    def cli(self, *arguments, check=True):
        started = time.monotonic()
        result = subprocess.run([*self.compose, *arguments], capture_output=True, text=True, timeout=45)
        record = {'argv': [*self.compose, *arguments], 'exit_status': result.returncode,
                  'stdout': result.stdout, 'stderr': result.stderr, 'seconds': time.monotonic()-started}
        self.commands.append(record)
        (self.directory / 'native-spark-commands.json').write_text(json.dumps(self.commands, indent=2)+'\n')
        if check:
            assert result.returncode == 0, record
        return result

    def endpoint(self, service, port):
        authority = self.cli('port', service, str(port)).stdout.strip()
        assert authority.startswith('127.0.0.1:'), authority
        return 'http://' + authority

    def http(self, url, data=None, password=None, username='module-test-user'):
        assert urllib.parse.urlsplit(url).hostname == '127.0.0.1', url
        headers = {'Content-Type': 'application/json' if isinstance(data, dict) else 'application/x-www-form-urlencoded'}
        if password is not None:
            headers['Authorization'] = 'Basic ' + base64.b64encode((username+':'+password).encode()).decode()
        body = json.dumps(data).encode() if isinstance(data, dict) else data
        request = urllib.request.Request(url, data=body, headers=headers)
        started = time.monotonic()
        record = {'url': url, 'request': body.decode() if body is not None else None}
        try:
            try:
                response = urllib.request.urlopen(request, timeout=20)
            except urllib.error.HTTPError as error:
                response = error
            with response:
                record.update(status=response.status, headers=dict(response.headers), body=response.read().decode(errors='replace'))
        except (urllib.error.URLError, http.client.RemoteDisconnected, ConnectionResetError, TimeoutError) as error:
            record.update(status=None, error_type=type(error).__name__, error=str(error), body='')
        record['seconds'] = time.monotonic()-started
        self.requests.append(record)
        (self.directory / 'native-spark-http.json').write_text(json.dumps(self.requests, indent=2)+'\n')
        return record

    @staticmethod
    def wait(callback, seconds=30):
        deadline = time.monotonic()+seconds
        while True:
            value = callback()
            if value:
                return value
            if time.monotonic() >= deadline:
                raise AssertionError('Native Spark readiness deadline exceeded')
            time.sleep(0.1)
