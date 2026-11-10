"""Native observations of real NiFi components; no Framework protocol helpers."""

import json
import os
from pathlib import Path
import re
import sys

from api import NativeClient, NifiTarget, wait_until


def seed(target):
    match = re.search(r"htpasswd -bc [^ ]+ ([^ ]+) ([^\s]+)", Path("test/module_targets/http/Dockerfile").read_text())
    assert match
    username, password = match.groups()
    for supplied, expected in [(None, "401"), (username + ":wrong-password", "401"), (username + ":" + password, "200")]:
        argv = ["curl", "--silent", "--show-error", "--output", "/dev/null", "--write-out", "%{http_code}"]
        if supplied:
            argv += ["--user", supplied]
        assert target.execute(*argv, "http://unrelated/protected/").decode() == expected
    created = target.create("processors", "Module target stored HTTP credential", "org.apache.nifi.processors.standard.GetHTTP")
    identifier = created["id"]
    status, _, raw = target.request("/nifi-api/processors/" + identifier, method="PUT", data={
        "revision": created["revision"], "component": {"id": identifier, "config": {
            "properties": {"URL": "http://unrelated/protected/?module_target_seed=nifi-execution", "Filename": "module-target-protected-content", "Username": username, "Password": password},
            "autoTerminatedRelationships": ["success"], "schedulingPeriod": "3600 sec",
        }},
    })
    assert status == 200, (status, raw)
    wait_until(lambda: (lambda item: item if item["component"]["validationStatus"] == "VALID" else None)(target.entity("processors", identifier)))
    target.run_state("processors", identifier, "RUNNING")
    observed = wait_until(lambda: (lambda item: item if item["status"]["aggregateSnapshot"]["bytesWritten"] == 114 else None)(target.entity("processors", identifier)))
    target.run_state("processors", identifier, "STOPPED")
    wait_until(lambda: target.quiescent("processors", identifier, "STOPPED"))
    return {"id": identifier, "username": username, "password": password, "initial_status": observed["status"], "state": "STOPPED"}


def snapshot(target):
    files = target.execute("find", "/tmp", "-mindepth", "1", "-maxdepth", "1", "-printf", "%p\n").decode().splitlines()
    return {"graph": target.graph(), "temporary_paths": sorted(files)}


def control(target):
    before = target.graph()
    proof = "/tmp/module-target-nifi-native-proof"
    receipts = []
    for repeat in (1, 2):
        target.execute("test", "!", "-e", proof)
        created = target.create("processors", "Native process control", "org.apache.nifi.processors.standard.ExecuteProcess")
        identifier = created["id"]
        try:
            status, _, raw = target.request("/nifi-api/processors/" + identifier, method="PUT", data={
                "revision": {"clientId": "x", "version": 1}, "component": {"id": identifier, "state": "RUNNING", "config": {
                    "properties": {"Command": "bash", "Command Arguments": '-c "id > ' + proof + '"'},
                    "autoTerminatedRelationships": ["success"], "schedulingPeriod": "3600 sec",
                }},
            })
            assert status == 200, (status, raw)
            content = wait_until(lambda: (lambda value: value if value.startswith("uid=1000(nifi)") else None)(target.execute("sh", "-c", "if test -f " + proof + "; then cat " + proof + "; fi").decode()))
            receipts.append({"repeat": repeat, "proof": content})
        finally:
            target.remove("processors", identifier)
            target.execute("rm", "-f", proof)
        wait_until(lambda: target.graph() == before)
    return receipts


def restore(target, before, owned):
    current = target.graph()
    new_processors = {item["id"] for item in current["processors"]} - {item["id"] for item in before["graph"]["processors"]}
    new_services = {item["id"] for item in current["services"]} - {item["id"] for item in before["graph"]["services"]}
    assert new_processors <= set(owned.get("processors", [])), (new_processors, owned)
    assert new_services <= set(owned.get("services", [])), (new_services, owned)
    for identifier in sorted(new_processors):
        target.remove("processors", identifier)
    for identifier in sorted(new_services):
        target.remove("controller-services", identifier)
    assert target.graph() == before["graph"]
    return {"kind": "Explicit native operator restoration after captured module state", "processors_removed": sorted(new_processors), "services_removed": sorted(new_services)}


def main():
    action, service, tag = sys.argv[1:4]
    assert re.fullmatch(r"[a-zA-Z0-9_-]+", tag), tag
    runtime = json.loads(Path(os.environ["MODULE_TARGET_RUNTIME"]).read_text())
    client = NativeClient(runtime, "native-" + tag + ".json")
    facts_path = Path(runtime["artifacts"]) / "nifi-execution-facts.json"
    try:
        if action == "preflight":
            target = NifiTarget(client, service)
            facts = target.verify()
            facts["identity"] = target.execute("id").decode().strip()
            assert facts["identity"].startswith("uid=1000(nifi) gid=1000(nifi)"), facts
            target.execute("java", "-version")
            facts["h2_jars"] = target.execute("find", "/opt/nifi/nifi-toolkit-current/lib", "-name", "h2*.jar", "-print").decode().splitlines()
            facts["canary"] = seed(target)
            facts["native_execution_controls"] = control(target)
            facts["initial_snapshot"] = snapshot(target)
            facts_path.write_text(json.dumps(facts, indent=2) + "\n")
            return facts
        facts = json.loads(facts_path.read_text())
        assert facts["service"] == service
        target = NifiTarget(client, service, token=facts["token"])
        if action == "snapshot":
            return snapshot(target)
        if action == "restore":
            return restore(target, json.loads(sys.argv[4]), json.loads(sys.argv[5]))
        if action == "verify-canary":
            return verify_canary(target, facts, client)
        raise ValueError("Unknown native operation " + action)
    finally:
        client.save()


def verify_canary(target, facts, client):
    identifier = facts["canary"]["id"]
    current = target.entity("processors", identifier)
    original = current["component"]["config"]["properties"]["URL"]
    status, _, raw = target.request("/nifi-api/processors/" + identifier, method="PUT", data={"revision": current["revision"], "component": {"id": identifier, "config": {"properties": {"URL": original + "-final-replay"}}}})
    assert status == 200, (status, raw)
    before_count = current["status"]["aggregateSnapshot"]["taskCount"]
    target.run_state("processors", identifier, "RUNNING")
    wait_until(lambda: (lambda item: item if item["status"]["aggregateSnapshot"]["taskCount"] > before_count else None)(target.entity("processors", identifier)))
    target.run_state("processors", identifier, "STOPPED")
    current = wait_until(lambda: target.quiescent("processors", identifier, "STOPPED"))
    logs = client.command(*client.runtime["compose"], "logs", "--no-color", "unrelated").decode()
    pattern = re.escape(facts["canary"]["username"]) + r'.*"GET /protected/\?module_target_seed=nifi-execution-final-replay HTTP/1\.1" (?:200|304) '
    assert re.search(pattern, logs), logs
    status, _, raw = target.request("/nifi-api/processors/" + identifier, method="PUT", data={"revision": current["revision"], "component": {"id": identifier, "config": {"properties": {"URL": original}}}})
    assert status == 200, (status, raw)
    return {"actual_authenticated_http": True, "original_url_restored": True, "kind": "Explicit final native canary replay, after module graph assertions"}


if __name__ == "__main__":
    print(json.dumps(main()))
