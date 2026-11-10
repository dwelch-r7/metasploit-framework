"""Real NiFi component operations using the existing independent HTTP client."""

from pathlib import Path
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "nifi"))
from client import NativeClient
from discovery import PROFILES, ScriptSources, probe
from urllib.parse import urlsplit


def wait_until(predicate, seconds=20):
    deadline = time.monotonic() + seconds
    while True:
        result = predicate()
        if result:
            return result
        if time.monotonic() >= deadline:
            raise TimeoutError("Native NiFi state did not reach the required value")
        time.sleep(0.1)


class NifiTarget:
    def __init__(self, client, service, profile_name=None, token=None):
        self.client = client
        self.service = service
        self.profile_name = profile_name or service
        self.profile = PROFILES[self.profile_name]
        self.token = token
        if self.profile["secure"] and token is None:
            accounts = dict(line.split("=", 1) for line in Path("test/module_targets/nifi/accounts.env").read_text().splitlines())
            status, _, raw = self.request("/nifi-api/access/token", form=True, data={
                "username": accounts["SINGLE_USER_CREDENTIALS_USERNAME"],
                "password": accounts["SINGLE_USER_CREDENTIALS_PASSWORD"],
            })
            assert status == 201, (status, raw)
            self.token = raw.decode().strip()
        status, group, raw = self.request("/nifi-api/process-groups/root")
        assert status == 200, (status, raw)
        self.group = group["id"]

    def request(self, route, **kwargs):
        kwargs.setdefault("token", self.token)
        return self.client.request(
            self.service, route, secure=self.profile["secure"],
            host_header=self.profile_name + ":" + str(self.profile["port"]),
            **kwargs,
        )

    def verify(self):
        status, configuration, raw = self.request("/nifi-api/access/config", token=None)
        assert status == 200 and configuration["config"]["supportsLogin"] == self.profile["secure"], (status, raw)
        status, about, raw = self.request("/nifi-api/flow/about")
        assert status == 200 and about["about"]["version"] == self.profile["version"], (status, raw)
        status, _, raw = self.request("/nifi/")
        assert status == 200, (status, raw)
        parser = ScriptSources()
        parser.feed(raw.decode())
        namespaces = [urlsplit(path) for path in parser.sources if urlsplit(path).path.endswith("/nf-namespace.js")]
        assert len(namespaces) == 1 and namespaces[0].query == self.profile["version"], parser.sources
        if self.profile["secure"]:
            assert self.request("/nifi-api/flow/about", token=None)[0] == 401
            assert self.request("/nifi-api/flow/about", token="module-target-invalid-bearer")[0] == 401
        return {**self.profile, "profile_name": self.profile_name, "service": self.service, "token": self.token, "root_group": self.group}

    def execute(self, *argv):
        return self.client.execute(self.service, *argv)

    def entity(self, kind, identifier):
        status, document, raw = self.request("/nifi-api/" + kind + "/" + identifier)
        assert status == 200, (status, raw)
        return document

    def types(self, kind):
        status, document, raw = self.request("/nifi-api/flow/" + kind + "-types")
        assert status == 200, (status, raw)
        return document["processorTypes" if kind == "processor" else "controllerServiceTypes"]

    def create(self, kind, name, component_type):
        candidates = self.types("processor" if kind == "processors" else "controller-service")
        descriptor = next(item for item in candidates if item["type"] == component_type)
        status, created, raw = self.request("/nifi-api/process-groups/" + self.group + "/" + kind, data={
            "revision": {"version": 0},
            "component": {"type": descriptor["type"], "bundle": descriptor["bundle"], "name": name, "position": {"x": 0, "y": 0}},
        })
        assert status == 201, (status, raw)
        return created

    def run_state(self, kind, identifier, state):
        current = self.entity(kind, identifier)
        status, document, raw = self.request("/nifi-api/" + kind + "/" + identifier + "/run-status", method="PUT", data={
            "revision": current["revision"], "state": state, "disconnectedNodeAcknowledged": False,
        })
        assert status == 200, (status, raw)
        return document

    def remove(self, kind, identifier):
        current = self.entity(kind, identifier)
        state = "STOPPED" if kind == "processors" else "DISABLED"
        if current["component"]["state"] != state:
            self.run_state(kind, identifier, state)
        current = wait_until(lambda: self.quiescent(kind, identifier, state))
        status, _, raw = self.request("/nifi-api/" + kind + "/" + identifier + "?version=" + str(current["revision"]["version"]), method="DELETE")
        assert status == 200, (status, raw)

    def quiescent(self, kind, identifier, state):
        current = self.entity(kind, identifier)
        active = current.get("status", {}).get("aggregateSnapshot", {}).get("activeThreadCount", 0)
        return current if current["component"]["state"] == state and active == 0 else None

    def graph(self):
        status, processors, raw = self.request("/nifi-api/process-groups/" + self.group + "/processors")
        assert status == 200, (status, raw)
        status, services, raw = self.request("/nifi-api/flow/process-groups/" + self.group + "/controller-services")
        assert status == 200, (status, raw)
        return {
            "processors": sorted((item["component"] for item in processors["processors"]), key=lambda item: item["id"]),
            "services": sorted((item["component"] for item in services["controllerServices"]), key=lambda item: item["id"]),
        }
