"""Bridge guarded campaign runtime to the independent Superset native controls."""
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / 'superset'))
from native_http import NativeHTTP
from native_probe import main as native_main


runtime = json.loads(Path(sys.argv[1]).read_text())
phase = sys.argv[2]
assert phase in ['before', 'after']
artifacts = Path(runtime['artifacts']) / ('native-' + phase)
artifacts.mkdir()
endpoint = runtime['endpoints']['gateway']
native_runtime = {'compose': runtime['compose'], 'origin': 'http://127.0.0.1:' + str(endpoint['port']),
                  'artifacts': str(artifacts), 'source_sha256': {
                      name: value['sha256'] for name, value in json.loads(
                          Path(__file__).resolve().parent.parent.joinpath('superset/sources.json').read_text()).items()}}
config = artifacts / 'runtime.json'
config.write_text(json.dumps(native_runtime, indent=2) + '\n')
if phase == 'before':
    sys.argv = [sys.argv[0], str(config)]
    native_main()
else:
    native = NativeHTTP(runtime['compose'], native_runtime['origin'], artifacts)
    try:
        result = native.cookie_controls()
        before = json.loads(Path(runtime['artifacts'], 'native-before/native-result.json').read_text())['seed']
        after = native.app('state')
        assert before == after, 'Owner tests changed logical application state'
        (artifacts / 'native-result.json').write_text(json.dumps(
            {'status': 'native_passed', 'cookie_controls': result, 'baseline': before, 'after': after}, indent=2) + '\n')
    finally:
        native.save()
