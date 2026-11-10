"""Independent genuine OpenTSDB HTTP and container CLI observations."""

import base64
import json
import pathlib
import subprocess
import urllib.error
import urllib.parse
import urllib.request


class OpenTsdbTarget:
    def __init__(self, runtime):
        self.runtime = runtime
        self.commands = []
        self.requests = []

    def command(self, service, *arguments, expected=0, input_data=None, timeout=30):
        argv = self.runtime["compose"] + ["exec", "-T", service, *arguments]
        result = subprocess.run(argv, input=input_data, capture_output=True, timeout=timeout)
        row = {"service": service, "argv": argv, "exitstatus": result.returncode,
               "stdout": result.stdout.decode("utf-8"), "stderr": result.stderr.decode("utf-8")}
        self.commands.append(row)
        self.save()
        assert result.returncode == expected, row
        return row

    def request(self, service, path, method="GET", document=None, auth=None):
        endpoint = self.runtime["endpoints"][service]
        url = "http://{}:{}{}".format(endpoint["host"], endpoint["port"], path)
        headers = {}
        data = None
        if document is not None:
            headers["Content-Type"] = "application/json"
            data = json.dumps(document).encode("utf-8")
        if auth:
            value = base64.b64encode(":".join(auth).encode("utf-8")).decode("ascii")
            headers["Authorization"] = "Basic " + value
        request = urllib.request.Request(url, headers=headers, method=method, data=data)
        try:
            response = urllib.request.urlopen(request, timeout=15)
        except urllib.error.HTTPError as error:
            response = error
        with response:
            body = response.read()
            try:
                text = body.decode("utf-8")
                encoding = "utf-8"
            except UnicodeDecodeError:
                text = base64.b64encode(body).decode("ascii")
                encoding = "base64"
            row = {"service": service, "path": path, "method": method,
                   "auth_user": auth[0] if auth else None, "code": response.status,
                   "headers": dict(response.headers), "body_encoding": encoding, "body": text}
        self.requests.append(row)
        self.save()
        return row, body

    def get(self, service, path, params=None, auth=None):
        if params:
            path += "?" + urllib.parse.urlencode(params)
        return self.request(service, path, auth=auth)

    def save(self):
        root = pathlib.Path(self.runtime["artifacts"])
        for name, rows in [("commands", self.commands), ("http", self.requests)]:
            (root / ("native-opentsdb-" + name + ".json")).write_text(json.dumps(rows, indent=2) + "\n")
