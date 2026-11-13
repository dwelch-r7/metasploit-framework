"""Independent selected-release controls without changing shared NiFi probes."""

import argparse
import json
import os
from pathlib import Path
import sys
from urllib.parse import urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "nifi"))
from client import NativeClient
from discovery import PROFILES, ScriptSources


def probe(client, service):
    profile = PROFILES[service]
    accounts = dict(line.split("=", 1) for line in Path("test/module_targets/nifi/accounts.env").read_text().splitlines())
    username = accounts["SINGLE_USER_CREDENTIALS_USERNAME"]
    password = accounts["SINGLE_USER_CREDENTIALS_PASSWORD"]

    def request(route, **kwargs):
        return client.request(service, route, secure=profile["secure"],
                              host_header=service + ":" + str(profile["port"]), **kwargs)

    status, configuration, raw = request("/nifi-api/access/config")
    assert status == 200 and configuration["config"]["supportsLogin"] == profile["secure"], (status, raw)
    for route in ("/nifi/", "/nifi/login"):
        status, _, raw = request(route)
        assert status == 200, (route, status)
        parser = ScriptSources()
        parser.feed(raw.decode())
        namespaces = [urlsplit(path) for path in parser.sources if urlsplit(path).path.endswith("/nf-namespace.js")]
        assert len(namespaces) == 1 and namespaces[0].query == profile["version"], parser.sources
    token = None
    if profile["secure"]:
        status, _, raw = request("/nifi-api/access/token", data={"username": username, "password": "wrong-password"}, form=True)
        assert status == 400, (status, raw)
        assert request("/nifi-api/flow/about")[0] == 401
        status, _, raw = request("/nifi-api/access/token", data={"username": username, "password": password}, form=True)
        assert status == 201, (status, raw)
        token = raw.decode().strip()
        status, current, raw = request("/nifi-api/flow/current-user", token=token)
        assert status == 200 and current["identity"] == username and not current["anonymous"], (status, raw)
    status, about, raw = request("/nifi-api/flow/about", token=token)
    assert status == 200 and about["about"]["version"] == profile["version"], (status, raw)
    status, _, missing = request("/module-target-missing/nifi/")
    assert status == 200 and b"Did you mean:" in missing, (status, missing)
    parser = ScriptSources()
    parser.feed(missing.decode())
    assert not parser.sources, parser.sources
    identity = client.execute(service, "id").decode().strip()
    assert identity.startswith("uid=1000(nifi) gid=1000(nifi)"), identity
    client.execute(service, "java", "-version")
    status, document, raw = request("/nifi-api/flow/process-groups/root", token=token)
    assert status == 200, (status, raw)
    flow = document["processGroupFlow"]["flow"]
    flow_ids = {kind: sorted(row["id"] for row in values) for kind, values in flow.items() if isinstance(values, list)}
    properties = client.execute(service, "sh", "-c", 'sha256sum "$NIFI_HOME/conf/nifi.properties"').decode().split()[0]
    facts = {"profiles": {service: {**profile, "identity": identity, "username": username if token else None,
                                    "flow_ids": flow_ids, "properties_sha256": properties}}}
    if "unrelated" in client.runtime["endpoints"]:
        status, _, raw = client.request("unrelated", "/plain.txt")
        assert status == 200 and raw == Path("test/module_targets/http/htdocs/plain.txt").read_bytes()
        assert client.request("unrelated", "/nifi/login")[0] == 404
        facts["unrelated"] = True
    client.records["facts"] = facts
    client.save()
    return facts


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("profile", choices=PROFILES)
    parser.add_argument("phase", choices=["before", "after"])
    args = parser.parse_args()
    runtime = json.loads(Path(os.environ["MODULE_TARGET_RUNTIME"]).read_text())
    client = NativeClient(runtime, "native-nifi-discovery-" + args.phase + ".json")
    try:
        print(json.dumps(probe(client, args.profile)))
    finally:
        client.save()
