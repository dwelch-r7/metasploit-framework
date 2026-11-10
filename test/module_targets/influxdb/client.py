"""Independent native CLI/HTTP observations of genuine InfluxDB containers."""

import base64
import json
import pathlib
import subprocess
import urllib.error
import urllib.parse
import urllib.request

ROOT = ("root", "root")
READER = ("module_reader", "module-reader-password")
POINT_QUERY = 'SELECT * FROM "module_metrics"."autogen"."temperature"'


class InfluxTarget:
    def __init__(self, runtime):
        self.runtime = runtime
        self.commands = []
        self.requests = []

    def command(self, service, *arguments, expected=0):
        argv = self.runtime["compose"] + ["exec", "-T", service, *arguments]
        result = subprocess.run(argv, capture_output=True, timeout=15)
        row = {
            "service": service, "argv": argv, "exitstatus": result.returncode,
            "stdout": result.stdout.decode("utf-8"), "stderr": result.stderr.decode("utf-8"),
        }
        self.commands.append(row)
        assert result.returncode == expected, row
        return row["stdout"]

    def cli(self, service, query, auth=ROOT):
        args = ["influx", "-host", "127.0.0.1", "-format", "json", "-precision", "rfc3339"]
        if auth:
            args += ["-username", auth[0], "-password", auth[1]]
        return self.command(service, *args, "-execute", query)

    def request(self, service, path, auth=ROOT, method="GET", body=None):
        endpoint = self.runtime["endpoints"][service]
        url = "http://{}:{}{}".format(endpoint["host"], endpoint["port"], path)
        headers = {}
        if auth:
            value = base64.b64encode(":".join(auth).encode("utf-8")).decode("ascii")
            headers["Authorization"] = "Basic " + value
        message = urllib.request.Request(url, headers=headers, data=body, method=method)
        try:
            response = urllib.request.urlopen(message, timeout=10)
        except urllib.error.HTTPError as error:
            response = error
        with response:
            row = {
                "service": service, "path": path, "method": method,
                "auth_user": auth[0] if auth else None,
                "code": response.status, "headers": dict(response.headers),
                "body": response.read().decode("utf-8"),
            }
        self.requests.append(row)
        return row

    def query(self, service, query, auth=ROOT, base="/"):
        return self.request(service, base.rstrip("/") + "/query?" + urllib.parse.urlencode({"q": query}), auth=auth)

    def state(self, service):
        queries = ["SHOW DATABASES", "SHOW USERS"]
        if service != "empty":
            queries.append(POINT_QUERY)
        rows = []
        for query in queries:
            response = self.query(service, query)
            assert response["code"] == 200, response
            rows.append(json.loads(response["body"]))
        return rows

    def save(self):
        root = pathlib.Path(self.runtime["artifacts"])
        for name, rows in [("commands", self.commands), ("http", self.requests)]:
            (root / ("native-influx-" + name + ".json")).write_text(json.dumps(rows, indent=2) + "\n")
