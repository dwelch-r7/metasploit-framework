"""Native HTTP/CLI observations of real NiFi containers, without Framework helpers."""

import base64
import json
from pathlib import Path
import ssl
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request


class NativeClient:
    def __init__(self, runtime, artifact_name):
        self.runtime = runtime
        self.artifact = Path(runtime["artifacts"]) / artifact_name
        self.records = {"commands": [], "http": [], "facts": {}}
        self.opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}),
            urllib.request.HTTPSHandler(context=ssl._create_unverified_context()),
        )

    def save(self):
        self.artifact.write_text(json.dumps(self.records, indent=2) + "\n")

    def command(self, *argv):
        started = time.monotonic()
        try:
            result = subprocess.run(list(argv), capture_output=True, timeout=30)
        except subprocess.TimeoutExpired as error:
            self.records["commands"].append({
                "argv": list(argv), "timeout_seconds": error.timeout,
                "seconds": time.monotonic() - started,
                "stdout_base64": base64.b64encode(error.stdout or b"").decode(),
                "stderr_base64": base64.b64encode(error.stderr or b"").decode(),
            })
            self.save()
            raise
        self.records["commands"].append({
            "argv": list(argv),
            "exitstatus": result.returncode,
            "seconds": time.monotonic() - started,
            "stdout_base64": base64.b64encode(result.stdout).decode(),
            "stderr_base64": base64.b64encode(result.stderr).decode(),
        })
        self.save()
        if result.returncode:
            raise RuntimeError(f"Native command failed: {argv}: {result.returncode}")
        return result.stdout

    def execute(self, service, *argv):
        return self.command(*self.runtime["compose"], "exec", "-T", service, *argv)

    def request(self, service, route, *, secure=False, host_header=None,
                data=None, token=None, method=None, form=False):
        endpoint = self.runtime["endpoints"][service]
        url = ("https" if secure else "http") + "://" + endpoint["host"] + ":" + str(endpoint["port"]) + route
        headers = {}
        if host_header:
            headers["Host"] = host_header
        if token:
            headers["Authorization"] = "Bearer " + token
        if data is None:
            body = None
        elif form:
            body = urllib.parse.urlencode(data).encode()
            headers["Content-Type"] = "application/x-www-form-urlencoded"
        else:
            body = json.dumps(data).encode()
            headers["Content-Type"] = "application/json"
        request = urllib.request.Request(url, data=body, headers=headers, method=method)
        started = time.monotonic()
        try:
            response = self.opener.open(request, timeout=20)
        except urllib.error.HTTPError as error:
            response = error
        except (urllib.error.URLError, TimeoutError) as error:
            self.records["http"].append({
                "service": service, "url": url, "method": request.get_method(),
                "request_headers": headers, "request": data, "error": repr(error),
                "seconds": time.monotonic() - started,
            })
            self.save()
            raise
        raw = response.read()
        self.records["http"].append({
            "service": service, "url": url, "method": request.get_method(),
            "response_url": response.geturl(),
            "request_headers": headers, "request": data, "status": response.status,
            "seconds": time.monotonic() - started,
            "response_headers": dict(response.headers),
            "body_base64": base64.b64encode(raw).decode(),
            "tls_verification": "Local self-signed fixture, certificate verification disabled" if secure else None,
        })
        self.save()
        try:
            document = json.loads(raw)
        except (ValueError, UnicodeDecodeError):
            document = None
        return response.status, document, raw
