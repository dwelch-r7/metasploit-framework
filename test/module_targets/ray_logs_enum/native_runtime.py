"""Apply modern native controls to the guarded owner's actual service."""
import json
from pathlib import Path
import subprocess
import sys
import uuid

runtime = json.loads(Path(sys.argv[1]).read_text())
phase = sys.argv[2]
assert phase in ['before', 'after']
base = Path(__file__).resolve().parents[1]
component = base / 'ray_logs'
artifacts = Path(runtime['artifacts'])
work = artifacts / ('native-' + phase)
work.mkdir()
commands = []
def target(action, **options):
    source = (component / 'native_target.py').read_text()
    argv = runtime['compose'] + ['exec', '-T', 'ray', 'python', '-c', source, json.dumps(dict(action=action, **options))]
    value = subprocess.run(argv, capture_output=True, text=True, timeout=120)
    commands.append({'argv': argv, 'exitstatus': value.returncode, 'stdout': value.stdout, 'stderr': value.stderr})
    assert value.returncode == 0, commands[-1]
    lines = [line.split(':', 1)[1] for line in value.stdout.splitlines() if line.startswith('MODULE_TARGET_RAY_LOGS_JSON:')]
    assert len(lines) == 1
    return json.loads(lines[0])

endpoints = {}
for name, service, port in [('head', 'ray', '8265'), ('agent', 'ray', '52365'), ('unrelated', 'unrelated', '80')]:
    result = subprocess.run(runtime['compose'] + ['port', service, port], capture_output=True, text=True, timeout=15)
    assert result.returncode == 0
    binding = result.stdout.strip()
    assert binding.startswith('127.0.0.1:') and binding.rsplit(':', 1)[1].isdigit()
    endpoints[name] = 'http://' + binding
config = {'compose': runtime['compose'], 'endpoints': endpoints, 'artifacts': str(work),
          'source_manifest': json.loads((component / 'sources-2.56.0.json').read_text())}
config_path = work / 'runtime.json'
config_path.write_text(json.dumps(config, indent=2) + '\n')
fixture_path = artifacts / 'owner-fixtures.json'
try:
    if phase == 'after':
        fixture = json.loads(fixture_path.read_text())
        assert target('verify', fixture=fixture)['fixture_bytes_unchanged']
        assert target('sdk', fixture=fixture, policy='traversable')['exact_owned_log_bytes']
        assert target('cleanup', fixture=fixture)['owned_fixture_paths_absent']
    subprocess.run(['python3', '-B', str(component / 'native_probe.py'), str(config_path)], check=True, timeout=300)
    if phase == 'before':
        result = json.loads((work / 'native-result.json').read_text())
        fixture = target('seed', nonce=uuid.uuid4().hex, node_id=result['fixture']['node_id'])
        fixture_path.write_text(json.dumps(fixture, indent=2) + '\n')
        assert target('sdk', fixture=fixture, policy='traversable')['exact_owned_log_bytes']
finally:
    (work / 'owner-fixture-commands.json').write_text(json.dumps(commands, indent=2) + '\n')
    source = (base / 'ray/diagnostics.py').read_text()
    result = subprocess.run(runtime['compose'] + ['exec', '-T', 'ray', 'python', '-c', source], capture_output=True, text=True, timeout=30)
    (work / 'ray-internal-diagnostics.json').write_text(json.dumps({'exitstatus': result.returncode, 'stdout': result.stdout, 'stderr': result.stderr}, indent=2) + '\n')
    assert result.returncode == 0, result.stderr
