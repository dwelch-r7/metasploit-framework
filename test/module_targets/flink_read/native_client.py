"""Real REST/vendor-command observations for task-owned Flink containers."""
import base64
import json
from pathlib import Path
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request


class NativeFlink:
    def __init__(self, runtime):
        self.runtime = runtime
        self.commands = []
        self.requests = []

    def process(self, argv, check=True):
        process = subprocess.run(argv, capture_output=True, timeout=60)
        record = dict(argv=argv, stdout_base64=base64.b64encode(process.stdout).decode(),
                      stderr=process.stderr.decode(errors='replace'), exitstatus=process.returncode)
        self.commands.append(record)
        if check:
            assert process.returncode == 0, record
        return process

    def command(self, service, *arguments, check=True):
        return self.process(self.runtime['compose'] + ['exec', '-T', service] + list(arguments), check)

    def request(self, service, path, *, method='GET', data=None, auth=None, content_type=None):
        endpoint = self.runtime['endpoints'][service]
        assert endpoint['host'] == '127.0.0.1'
        url = f"http://127.0.0.1:{endpoint['port']}{path}"
        if isinstance(data, dict):
            data = json.dumps(data).encode()
            content_type = 'application/json'
        request = urllib.request.Request(url, data=data, method=method)
        if auth:
            request.add_header('Authorization', 'Basic ' + base64.b64encode(':'.join(auth).encode()).decode())
        if content_type:
            request.add_header('Content-Type', content_type)
        started = time.monotonic()
        try:
            response = urllib.request.build_opener(urllib.request.ProxyHandler({})).open(request, timeout=40)
        except urllib.error.HTTPError as error:
            response = error
        body = response.read()
        self.requests.append(dict(service=service, method=method, url=url, auth=auth,
                                  request_body_base64=base64.b64encode(data or b'').decode(),
                                  status=response.code, headers=dict(response.headers),
                                  body_base64=base64.b64encode(body).decode(), seconds=time.monotonic()-started))
        try:
            document = json.loads(body)
        except (ValueError, UnicodeDecodeError):
            document = None
        return response.code, document, body

    def upload(self, service, name, data, prefix='', auth=None):
        boundary = 'module-target-flink-native-upload'
        body = (f'--{boundary}\r\nContent-Disposition: form-data; name="jarfile"; filename="{name}"\r\n'
                'Content-Type: application/x-java-archive\r\n\r\n').encode() + data + f'\r\n--{boundary}--\r\n'.encode()
        return self.request(service, prefix+'/jars/upload', method='POST', data=body, auth=auth,
                            content_type='multipart/form-data; boundary='+boundary)

    def upload_state(self, service):
        return dict(files=sorted(self.command(service, 'find', '/opt/flink/uploads', '-type', 'f', '-print').stdout.decode().splitlines()),
                    directories=sorted(self.command(service, 'find', '/opt/flink/uploads', '-type', 'd', '-print').stdout.decode().splitlines()))

    def restore_staging(self, service, before, captured_files):
        after = self.upload_state(service)
        added = sorted(set(after['files']) - set(before['files']))
        assert added == sorted(captured_files), (added, captured_files)
        for path in added:
            assert path.startswith('/opt/flink/uploads/') and '..' not in Path(path).parts
            self.command(service, 'unlink', path)
        directories = sorted(set(after['directories']) - set(before['directories']), key=len, reverse=True)
        for path in directories:
            assert path.startswith('/opt/flink/uploads/') and '..' not in Path(path).parts
            self.command(service, 'rmdir', path)
        assert self.upload_state(service) == before
        return dict(before=before, after_response=after, operator_removed_files=added,
                    operator_removed_directories=directories, restored=self.upload_state(service))

    def write(self, path, **extra):
        Path(path).write_text(json.dumps(dict(commands=self.commands, requests=self.requests, **extra), indent=2)+'\n')
