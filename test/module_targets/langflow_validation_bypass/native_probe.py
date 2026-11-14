"""Native authentication and execution controls for the real validation endpoint."""
from pathlib import Path
import importlib.util
import json
import os
import sys

action, tag = sys.argv[1:]
assert action in ('verify', 'health')
mode = os.environ['LANGFLOW_VALIDATION_BYPASS_PROFILE']
os.environ['LANGFLOW_PROFILE'] = 'auth' if mode.endswith('protected') else 'auto'
root = Path(__file__).parent
version_number = '1.2.0' if mode.startswith('pre-') else '1.3.2'
protected = mode.endswith('protected')
guarded_endpoint = version_number != '1.2.0'
spec = importlib.util.spec_from_file_location('native', root.parent/'langflow/native.py')
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
native = module.Native(tag)
status, body = native.http('/api/v1/version')
version = json.loads(body)
assert status == 200 and version['version'] == version_number, (status, version)
if action == 'health':
    print(json.dumps(version))
    sys.exit(0)
vendor = json.loads(native.execute('python', '-c', (root/'source_probe.py').read_text()))
vendor.pop('texts')
expected = json.loads((root/'vendor.json').read_text())['installed'][version_number]
assert vendor == expected, vendor
status, body = native.http('/api/v1/auto_login')
auto_login_status = status
assert status == (400 if protected else 200), (status, body)
if not protected:
    assert isinstance(json.loads(body)['access_token'], str) and json.loads(body)['access_token']

benign = {'code': 'def module_target_benign(value=1):\n return value\n'}
endpoint = '/api/v1/validate/code'
anonymous = native.http(endpoint, data=benign)
invalid = native.http(endpoint, 'module-target-invalid', data=benign)
assert anonymous[0] == (403 if protected and guarded_endpoint else 200), anonymous
assert invalid[0] == (401 if guarded_endpoint else 200), invalid
token = None
flow_token = None
if protected:
    assert native.http('/api/v1/flows/')[0] == 403
    assert native.http('/api/v1/flows/', 'module-target-invalid')[0] == 401
    status, body = native.http('/api/v1/login', form={'username': 'module-target-admin', 'password': 'module-target-native-password'})
    assert status == 200, (status, body)
    flow_token = json.loads(body)['access_token']
    if guarded_endpoint:
        token = flow_token
    assert native.http(endpoint, flow_token, data=benign)[0] == 200

def snapshot(tag):
    path = '/tmp/module-target-langflow-3248-' + tag
    native.execute('test', '!', '-e', path)
    expression = "__import__('json').dumps({'pid':__import__('os').getpid(),'uid':__import__('os').getuid(),'names':sorted(vars(__import__('builtins'))),'auto_login':__import__('langflow.services.deps',fromlist=['get_settings_service']).get_settings_service().auth_settings.AUTO_LOGIN,'lazy_load_components':getattr(__import__('langflow.services.deps',fromlist=['get_settings_service']).get_settings_service().settings,'lazy_load_components',None)})"
    code = 'def module_target_state(value=__import__("pathlib").Path(' + repr(path) + ').write_text(' + expression + ')):\n pass\n'
    status, body = native.http(endpoint, token, data={'code': code})
    assert status == 200, (status, body)
    value = json.loads(native.execute('python', '-c', 'from pathlib import Path;p=Path(' + repr(path) + ');print(p.read_text());assert p.stat().st_uid==1000;p.unlink();assert not p.exists()'))
    assert value['uid'] == 1000 and value['auto_login'] == (not protected)
    assert value['lazy_load_components'] == (None if version_number == '1.2.0' else False), value
    return value

baseline = snapshot('before')
status, body = native.http('/api/v1/flows/', flow_token)
assert status == 200, (status, body)
flows = json.loads(body)
proofs = []
for family in ['default', 'decorator']:
    for repeat in range(2):
        path = '/tmp/module-target-langflow-3248-native-' + family
        marker = 'native-3248-' + family + '-' + str(repeat)
        native.execute('test', '!', '-e', path)
        effect = 'with open(' + repr(path) + ',"a",encoding="utf-8") as output:\n output.write(' + repr(marker) + ')\n'
        code = ('def module_target_default(value=exec(' + repr(effect) + ')):\n return value\n' if family == 'default'
                else '@exec(' + repr(effect) + ')\ndef module_target_decorator():\n pass\n')
        status, body = native.http(endpoint, token, data={'code': code})
        assert status == 200, (status, body)
        observed = json.loads(native.execute('python', '-c', 'from pathlib import Path;import json;p=Path(' + repr(path) + ');print(json.dumps(dict(bytes=p.read_text(),uid=p.stat().st_uid,gid=p.stat().st_gid)));p.unlink();assert not p.exists()'))
        assert observed == {'bytes': marker, 'uid': 1000, 'gid': 0}, observed
        proofs.append({'family': family, 'repeat': repeat, 'observed': observed, 'response': json.loads(body)})
assert snapshot('after') == baseline
status, body = native.http('/api/v1/flows/', flow_token)
assert status == 200 and json.loads(body) == flows
print(json.dumps({'version': version, 'vendor': vendor, 'mode': mode, 'baseline': baseline,
                  'auto_login_status': auto_login_status, 'anonymous_validation_status': anonymous[0],
                  'invalid_bearer_status': invalid[0], 'proofs': proofs,
                  'flow_registry_unchanged': True, 'flows': flows}))
