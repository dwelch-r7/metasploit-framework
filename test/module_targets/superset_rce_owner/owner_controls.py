"""Native owner baseline and observation, with no automatic state repair."""
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import traceback

component = Path(__file__).resolve().parent.parent / 'superset_rce'
spec = importlib.util.spec_from_file_location('superset_native_rce_controls', component / 'native_probe.py')
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
NativeRCE = module.NativeRCE

runtime = json.loads(Path(sys.argv[1]).read_text())
action = sys.argv[2]
assert action in ['before', 'snapshot', 'verify']
assert sys.argv[3].isdigit() and int(sys.argv[3]) > 0
root = Path(runtime['artifacts'])
artifacts = root / ('owner-native-' + action + '-' + sys.argv[3])
assert not artifacts.exists()
artifacts.mkdir()
endpoint = runtime['endpoints']['gateway']
native = NativeRCE(runtime['compose'], 'http://127.0.0.1:' + str(endpoint['port']), artifacts)
result = {'status': 'failed', 'action': action, 'owner_calls_by_native_helper': 0}
try:
    if action == 'before':
        # First qualify cookie/DB controls in this exact invocation, then both
        # native SQL/permalink/deserialization cycles, before any owning call.
        argv = ['python3', '-B', 'test/module_targets/superset_cookie/native_runtime.py', sys.argv[1], 'before']
        process = subprocess.run(argv, capture_output=True, text=True, timeout=240)
        (artifacts / 'cookie-native-process.json').write_text(json.dumps({'argv': argv, 'exitstatus': process.returncode,
                                                                       'stdout': process.stdout, 'stderr': process.stderr}, indent=2) + '\n')
        assert process.returncode == 0, process.stderr
        native_runtime = root / 'native-before/runtime.json'
        argv = ['python3', '-B', str(component / 'native_probe.py'), str(native_runtime)]
        process = subprocess.run(argv, capture_output=True, text=True, timeout=300)
        (artifacts / 'rce-native-process.json').write_text(json.dumps({'argv': argv, 'exitstatus': process.returncode,
                                                                    'stdout': process.stdout, 'stderr': process.stderr}, indent=2) + '\n')
        assert process.returncode == 0, process.stderr
        native_result = json.loads((root / 'native-before/native-rce-result.json').read_text())
        assert native_result['status'] == 'native_passed' and native_result['restored']
        # Two valuable existing permalinks catch broad UPDATE damage and binary
        # restoration defects that an empty key-value table would conceal.
        browser, _, _ = native.login('lab-admin', 'module-target-superset-admin-password', accepted=True)
        csrf = json.loads(native.expect(browser, '/api/v1/security/csrf_token/', 200))['result']
        native.expect(browser, '/dashboard/new/', 302)
        import re
        location = dict(native.requests[-1]['headers_received'])['Location']
        dashboard_id = int(re.search(r'/dashboard/(\d+)/', location)[1])
        keys = []
        for index in range(2):
            response = json.loads(native.expect(browser, '/api/v1/dashboard/' + str(dashboard_id) + '/permalink', 201,
                                                method='POST', csrf=csrf,
                                                data={'filterState': {'nativeCanary': index}, 'urlParams': [['module', str(index)]]}))
            keys.append(response['key'])
            native.expect(browser, '/superset/dashboard/p/' + response['key'] + '/', 302)
        baseline = {'state': native.app('state'), 'raw': native.observe('snapshot'), 'keys': keys}
        assert len(baseline['state']['dashboards']) == 1 and len(baseline['state']['key_values']) == 3
        (root / 'owner-baseline.json').write_text(json.dumps(baseline, indent=2) + '\n')
        result['baseline'] = baseline
    else:
        baseline = json.loads((root / 'owner-baseline.json').read_text())
        result['state'] = native.app('state')
        result['raw'] = native.observe('snapshot')
        if action == 'verify':
            # Do not restore before comparing. Owner failure remains visible.
            assert result['state'] == baseline['state'], 'Owner did not restore selected native application state'
            for name in ['tab_state', 'table_schema', 'key_value']:
                assert result['raw'][name] == baseline['raw'][name], 'Owner changed ' + name
            browser, _, _ = native.login('lab-admin', 'module-target-superset-admin-password', accepted=True)
            for key in baseline['keys']:
                native.expect(browser, '/superset/dashboard/p/' + key + '/', 302)
    result['status'] = 'passed'
except BaseException as error:
    result['failure'] = {'type': type(error).__name__, 'message': str(error), 'traceback': traceback.format_exc()}
    raise
finally:
    native.save()
    (artifacts / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
