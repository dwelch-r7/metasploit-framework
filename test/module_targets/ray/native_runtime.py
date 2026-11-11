"""Use the proven native controls on the guarded owner's actual Ray service."""
import json
import os
from pathlib import Path
import subprocess
import sys
import uuid

from native_probe import NativeRay, main as native_main


runtime = json.loads(Path(sys.argv[1]).read_text())
phase = sys.argv[2]
assert phase in ['before', 'after']
artifacts = Path(runtime['artifacts']) / ('native-' + phase)
artifacts.mkdir()
shared = Path(__file__).resolve().parent
version = os.environ.get('MODULE_TARGET_RAY_VERSION', '2.6.3')
assert version in ['2.6.3', '2.8.1']
endpoints = {}
for name, service, port in [('head', 'ray', '8265'), ('agent', 'ray', '52365'), ('unrelated', 'unrelated', '80')]:
    argv = runtime['compose'] + ['port', service, port]
    result = subprocess.run(argv, capture_output=True, text=True, timeout=15)
    assert result.returncode == 0, result.stderr
    address = result.stdout.strip()
    assert address.startswith('127.0.0.1:') and address.rsplit(':', 1)[1].isdigit(), address
    endpoints[name] = 'http://' + address
config = {'compose': runtime['compose'], 'endpoints': endpoints, 'artifacts': str(artifacts),
          'source_manifest': json.loads((shared / ('sources-' + version + '.json')).read_text())}
path = artifacts / 'runtime.json'
path.write_text(json.dumps(config, indent=2) + '\n')
fixture_path = Path(runtime['artifacts']) / 'owner-fixtures.json'
native = NativeRay(config)
try:
    if phase == 'after':
        fixture = json.loads(fixture_path.read_text())
        verification = native.target('verify-fixtures', **fixture)
        assert verification['fixture_bytes_unchanged']
        assert native.target('cleanup', **fixture)['owned_fixture_paths_absent']
    sys.argv = [sys.argv[0], str(path)]
    native_main()
    if phase == 'before':
        nonce = uuid.uuid4().hex
        fixture = native.target('seed', nonce=nonce)
        fixture['nonce'] = nonce
        fixture_path.write_text(json.dumps(fixture, indent=2) + '\n')
finally:
    source = (shared / 'diagnostics.py').read_text()
    argv = runtime['compose'] + ['exec', '-T', 'ray', 'python', '-c', source]
    diagnostic = subprocess.run(argv, capture_output=True, text=True, timeout=30)
    (artifacts / 'ray-internal-diagnostics.json').write_text(json.dumps(
        {'argv': argv, 'exitstatus': diagnostic.returncode, 'stdout': diagnostic.stdout,
         'stderr': diagnostic.stderr}, indent=2) + '\n')
    assert diagnostic.returncode == 0, diagnostic.stderr
    (artifacts / 'owner-fixture-commands.json').write_text(json.dumps(native.commands, indent=2) + '\n')
