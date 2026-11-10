"""Independent HTTP/vendor-CLI controls for task-owned genuine Solr targets."""
import base64
import json
from pathlib import Path
import subprocess
import urllib.error
import urllib.parse
import urllib.request


class NativeSolr:
    def __init__(self, runtime):
        self.runtime = runtime
        self.commands = []
        self.requests = []

    def command(self, service, *arguments, check=True):
        argv = self.runtime['compose'] + ['exec', '-T', service] + list(arguments)
        return self.process(service, arguments, argv, check)

    def compose(self, *arguments, check=True):
        return self.process('compose', arguments, self.runtime['compose'] + list(arguments), check)

    def process(self, service, arguments, argv, check):
        process = subprocess.run(argv, capture_output=True, timeout=45)
        record = dict(service=service, argv=list(arguments),
                      stdout=process.stdout.decode(errors='replace'),
                      stderr=process.stderr.decode(errors='replace'),
                      exitstatus=process.returncode)
        self.commands.append(record)
        if check:
            assert process.returncode == 0, record
        return record

    def request(self, service, path, *, method='GET', query=None, data=None,
                content_type=None, auth=None):
        endpoint = self.runtime['endpoints'][service]
        assert endpoint['host'] == '127.0.0.1'
        url = f"http://{endpoint['host']}:{endpoint['port']}{path}"
        if query:
            url += '?' + urllib.parse.urlencode(query)
        if isinstance(data, dict):
            data = json.dumps(data).encode()
            content_type = 'application/json'
        request = urllib.request.Request(url, data=data, method=method)
        if content_type:
            request.add_header('Content-Type', content_type)
        if auth:
            request.add_header('Authorization', 'Basic ' + base64.b64encode(':'.join(auth).encode()).decode())
        try:
            response = urllib.request.build_opener(urllib.request.ProxyHandler({})).open(request, timeout=15)
        except urllib.error.HTTPError as error:
            response = error
        body = response.read()
        record = dict(service=service, method=method, url=url,
                      request_body_base64=base64.b64encode(data or b'').decode(),
                      status=response.code, headers=dict(response.headers),
                      body_base64=base64.b64encode(body).decode())
        self.requests.append(record)
        try:
            document = json.loads(body)
        except (ValueError, UnicodeDecodeError):
            document = None
        return response.code, document, body

    def write(self, path, **extra):
        Path(path).write_text(json.dumps(dict(commands=self.commands, requests=self.requests, **extra), indent=2) + '\n')
