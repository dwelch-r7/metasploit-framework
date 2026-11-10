"""Independent native gates for the NiFi version and login scanners."""

from html.parser import HTMLParser
import json
import os
from pathlib import Path
from urllib.parse import urlsplit

from client import NativeClient


PROFILES = {
    "legacy": {"version": "1.13.2", "secure": False, "port": 8080},
    "vulnerable": {"version": "1.21.0", "secure": True, "port": 8443},
    "fixed": {"version": "1.22.0", "secure": True, "port": 8443},
}


class ScriptSources(HTMLParser):
    def __init__(self):
        super().__init__()
        self.sources = []

    def handle_starttag(self, tag, attributes):
        if tag == "script":
            source = dict(attributes).get("src")
            if source:
                self.sources.append(source)


def probe(client):
    accounts = dict(line.split("=", 1) for line in Path("test/module_targets/nifi/accounts.env").read_text().splitlines())
    username = accounts["SINGLE_USER_CREDENTIALS_USERNAME"]
    password = accounts["SINGLE_USER_CREDENTIALS_PASSWORD"]
    facts = {"profiles": {}}
    for service, profile in PROFILES.items():
        def request(route, **kwargs):
            return client.request(service, route, secure=profile["secure"],
                                  host_header=service + ":" + str(profile["port"]), **kwargs)

        status, configuration, raw = request("/nifi-api/access/config")
        assert status == 200, (service, status, raw)
        assert configuration["config"]["supportsLogin"] == profile["secure"], configuration
        for route in ("/nifi/", "/nifi/login"):
            status, _, raw = request(route)
            assert status == 200, (service, route, status)
            parser = ScriptSources()
            parser.feed(raw.decode())
            namespaces = [urlsplit(path) for path in parser.sources if urlsplit(path).path.endswith("/nf-namespace.js")]
            assert len(namespaces) == 1 and namespaces[0].query == profile["version"], parser.sources
        token = None
        if profile["secure"]:
            status, _, raw = request("/nifi-api/access/token", data={"username": username, "password": "wrong-password"}, form=True)
            assert status == 400, (service, status, raw)
            assert request("/nifi-api/flow/about")[0] == 401
            status, _, raw = request("/nifi-api/access/token", data={"username": username, "password": password}, form=True)
            assert status == 201, (service, status, raw)
            token = raw.decode().strip()
            status, current, raw = request("/nifi-api/flow/current-user", token=token)
            assert status == 200 and current["identity"] == username and not current["anonymous"], (status, raw)
        status, about, raw = request("/nifi-api/flow/about", token=token)
        assert status == 200 and about["about"]["version"] == profile["version"], (service, status, raw)
        status, _, missing = request("/module-target-missing/nifi/")
        assert status == 200 and b"Did you mean:" in missing, (service, status, missing)
        parser = ScriptSources()
        parser.feed(missing.decode())
        assert not parser.sources, parser.sources
        identity = client.execute(service, "id").decode().strip()
        assert identity.startswith("uid=1000(nifi) gid=1000(nifi)"), identity
        client.execute(service, "java", "-version")
        facts["profiles"][service] = {**profile, "identity": identity, "username": username if token else None}
    status, _, raw = client.request("unrelated", "/plain.txt")
    assert status == 200 and raw == Path("test/module_targets/http/htdocs/plain.txt").read_bytes()
    assert client.request("unrelated", "/nifi/login")[0] == 404
    client.records["facts"] = facts
    client.save()
    return facts


if __name__ == "__main__":
    runtime = json.loads(Path(os.environ["MODULE_TARGET_RUNTIME"]).read_text())
    client = NativeClient(runtime, "native-nifi-discovery.json")
    try:
        print(json.dumps(probe(client)))
    finally:
        client.save()
