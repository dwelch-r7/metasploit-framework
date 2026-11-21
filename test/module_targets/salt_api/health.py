"""Check daemon liveness and a genuine TLS API route without running commands."""

from pathlib import Path
import json
import os
import ssl
import urllib.request

state = json.loads(Path('/var/run/salt/module-target-api.json').read_text())
for role in state['roles'].values():
    os.kill(role['pid'], 0)
url = 'https://127.0.0.1:8000' + state['prefix'].rstrip('/') + '/'
request = urllib.request.Request(url, headers={'Accept': 'application/json'})
with urllib.request.urlopen(request, context=ssl._create_unverified_context(), timeout=3) as response:
    assert response.status == 200
