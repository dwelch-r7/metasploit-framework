"""Require real native query/auth/row controls before module execution."""

import json
import os
from client import InfluxTarget, ROOT, READER, POINT_QUERY


def document(response, code=200):
    assert response["code"] == code, response
    return json.loads(response["body"])


def without_statement_ids(value):
    if isinstance(value, dict):
        return {key: without_statement_ids(child) for key, child in value.items() if key != "statement_id"}
    if isinstance(value, list):
        return [without_statement_ids(child) for child in value]
    return value


def names(value):
    series = value["results"][0]["series"][0]
    assert series["name"] == "databases" and series["columns"] == ["name"], series
    return sorted(row[0] for row in series.get("values", []))


runtime = json.loads(open(os.environ["MODULE_TARGET_RUNTIME"]).read())
api = InfluxTarget(runtime)
profiles = {}
try:
    for service in ["secured", "open", "empty"]:
        version = api.command(service, "influxd", "version")
        assert version == "InfluxDB v1.8.10 (git: 1.8 688e697c51fd)\n", version
        identity = api.command(service, "id")
        assert identity == "uid=0(root) gid=0(root) groups=0(root)\n", identity
        assert api.command(service, "cat", "/proc/1/comm") == "influxd\n"
        ping = api.request(service, "/ping")
        assert ping["code"] == 204 and ping["headers"]["X-Influxdb-Version"] == "1.8.10", ping
        root = api.request(service, "/")
        assert root["code"] == 404 and root["headers"]["X-Influxdb-Version"] == "1.8.10", root
        databases = document(api.query(service, "SHOW DATABASES"))
        assert names(databases) == ([] if service == "empty" else ["module private space", "module_metrics"]), databases
        cli = json.loads(api.cli(service, "SHOW DATABASES"))
        assert without_statement_ids(cli) == without_statement_ids(databases), (cli, databases)
        users = document(api.query(service, "SHOW USERS"))
        assert without_statement_ids(json.loads(api.cli(service, "SHOW USERS"))) == without_statement_ids(users)
        users_rows = users["results"][0]["series"][0]["values"]
        assert sorted(users_rows) == ([["module_reader", False]] if service == "open" else [["root", True]] if service == "empty" else [["module_reader", False], ["root", True]]), users
        for auth in [None, ("root", "incorrect-password"), ("absent-user", "incorrect-password")]:
            response = api.query(service, "SHOW DATABASES", auth=auth)
            if service == "open":
                assert document(response) == databases, response
            else:
                error = document(response, code=401)
                assert error["error"] in ["unable to parse authentication credentials", "authorization failed"], response
        if service != "empty":
            body = 'temperature,site=lab text="café ✓",value=21.5 1700000000000000000\ntemperature,site=lab text="quoted \\"value\\"",value=-4.25 1700000001000000000\n'
            write = api.request(service, "/write?db=module_metrics&precision=ns", method="POST", body=body.encode("utf-8"))
            assert write["code"] == 204, write
            points = document(api.query(service, POINT_QUERY))
            expected = {"results": [{"statement_id": 0, "series": [{"name": "temperature", "columns": ["time", "site", "text", "value"], "values": [["2023-11-14T22:13:20Z", "lab", "café ✓", 21.5], ["2023-11-14T22:13:21Z", "lab", 'quoted "value"', -4.25]]}]}]}
            assert points == expected, points
            assert without_statement_ids(json.loads(api.cli(service, POINT_QUERY))) == without_statement_ids(points)
        profiles[service] = {"version": version, "identity": identity, "databases": databases, "users": users}
    reader = document(api.query("secured", "SHOW DATABASES", auth=READER))
    assert names(reader) == ["module_metrics"], reader
    forbidden = document(api.query("secured", "SHOW USERS", auth=READER), code=403)
    assert "requires admin privilege" in forbidden["error"], forbidden
    profiles["reader"] = {"databases": reader, "forbidden": forbidden}
    query_cases = {"points": POINT_QUERY, "multi": "SHOW DATABASES; SHOW USERS", "no_rows": 'SELECT * FROM "module_metrics"."autogen"."absent_measurement"'}
    profiles["queries"] = {}
    for label, query in query_cases.items():
        value = document(api.query("secured", query))
        assert without_statement_ids(json.loads(api.cli("secured", query))) == without_statement_ids(value)
        profiles["queries"][label] = value
    assert profiles["queries"]["no_rows"] == {"results": [{"statement_id": 0}]}
    for query, code, reason in [("SELECT FROM", 400, "error parsing query")]:
        response = api.query("secured", query)
        assert reason in document(response, code=code)["error"], response
    missing = api.request("secured", "/missing/query?q=SHOW%20DATABASES")
    assert missing["code"] == 404 and missing["headers"]["X-Influxdb-Version"] == "1.8.10", missing
    assert api.request("prefix", "/influx/")["code"] == 404
    assert document(api.query("prefix", "SHOW DATABASES", base="/influx/")) == profiles["secured"]["databases"]
    assert document(api.query("prefix", POINT_QUERY, base="/influx/")) == profiles["queries"]["points"]
    assert document(api.query("prefix", "SHOW DATABASES", auth=("root", "incorrect-password"), base="/influx/"), code=401)["error"] == "authorization failed"
    unrelated = api.request("unrelated", "/")
    assert unrelated["code"] == 200 and "X-Influxdb-Version" not in unrelated["headers"], unrelated
    api.command("secured", "curl", "--silent", "--show-error", "--connect-timeout", "2", "http://127.0.0.1:8087/ping", expected=7)
    profiles["states"] = {service: api.state(service) for service in ["secured", "open", "empty"]}
finally:
    api.save()
print(json.dumps({"status": "passed", "profiles": profiles, "commands": len(api.commands), "http": len(api.requests)}))
