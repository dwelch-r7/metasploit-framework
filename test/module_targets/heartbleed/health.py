from pathlib import Path
import json
import os
import socket

providers = json.loads(Path('/tmp/heartbleed-lab/providers.json').read_text())
for provider in providers.values():
    os.kill(provider['pid'], 0)
    with socket.create_connection(('127.0.0.1', provider['port']), timeout=1):
        pass

for port in [2525, 12000, *range(10400, 11000, 100), *range(11400, 12000, 100)]:
    with socket.create_connection(('127.0.0.1', port), timeout=1):
        pass
