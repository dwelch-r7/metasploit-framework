"""Independent controls calibrated against the genuine pinned legacy component loader."""
from pathlib import Path
import importlib.util
import json
import os
import sys

action, tag = sys.argv[1:]
assert action in ('verify', 'health')
mode = os.environ['LANGFLOW_LEGACY_CUSTOM_PROFILE']
os.environ['LANGFLOW_PROFILE'] = 'auth' if mode == 'protected' else 'auto'
sys.path.insert(0, str(Path(__file__).parent))
from component_source import component_source

spec = importlib.util.spec_from_file_location('native', Path(__file__).parents[1] / 'langflow/native.py')
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
native = module.Native(tag)
status, body = native.http('/api/v1/version')
version = json.loads(body)
assert status == 200 and version['version'] == '1.3.2' and version['package'] == 'Langflow', (status, version)
if action == 'health':
    print(json.dumps(version))
    sys.exit(0)
vendor = json.loads(native.execute('python', '-c', Path(__file__).with_name('source_probe.py').read_text()))
vendor.pop('texts')
expected = json.loads(Path(__file__).with_name('vendor.json').read_text())['installed']
assert vendor == expected, vendor
endpoint = '/api/v1/custom_component'
anonymous = native.http(endpoint, data={'code': component_source(), 'frontend_node': {}})
assert anonymous[0] == (403 if mode == 'protected' else 200), anonymous
assert native.http(endpoint, 'module-target-invalid', data={'code': component_source(), 'frontend_node': {}})[0] == 401
token = None
if mode == 'protected':
    status, body = native.http('/api/v1/login', form={'username': 'module-target-admin', 'password': 'module-target-native-password'})
    assert status == 200, (status, body)
    token = json.loads(body)['access_token']
responses = []
for frontend in [None, {}]:
    data = {'code': component_source()}
    if frontend is not None:
        data['frontend_node'] = frontend
    status, body = native.http(endpoint, token, data=data)
    value = json.loads(body)
    assert status == 200 and isinstance(value.get('data'), dict) and value.get('type') == 'ModuleNativeComponent', (status, value)
    responses.append({'frontend_node': frontend, 'response': value})

def snapshot(tag):
    path = '/tmp/module-target-langflow-0769-' + tag
    native.execute('test', '!', '-e', path)
    expression = "__import__('json').dumps({'pid':__import__('os').getpid(),'uid':__import__('os').getuid(),'names':sorted(vars(__import__('builtins'))),'auto_login':__import__('langflow.services.deps',fromlist=['get_settings_service']).get_settings_service().auth_settings.AUTO_LOGIN,'lazy_load_components':__import__('langflow.services.deps',fromlist=['get_settings_service']).get_settings_service().settings.lazy_load_components})"
    effect = '__import__("pathlib").Path(' + repr(path) + ').write_text(' + expression + ')'
    prefix = 'module-target-backend:'
    status, body = native.http(endpoint, token, data={'code': component_source(class_effect=effect, display_prefix=prefix), 'frontend_node': {}})
    assert status == 200, (status, body)
    response = json.loads(body)
    value = json.loads(native.execute('python', '-c', 'from pathlib import Path;p=Path(' + repr(path) + ');print(p.read_text());assert p.stat().st_uid==1000;p.unlink();assert not p.exists()'))
    assert value['uid'] == 1000 and value['auto_login'] == (mode != 'protected') and value['lazy_load_components'] is False
    assert response['data']['display_name'] == prefix + str(value['pid']), (response, value)
    return value

baseline = snapshot('builtin-before')
status, body = native.http('/api/v1/flows/', token)
assert status == 200, (status, body)
flows = json.loads(body)
proofs = []
for frontend in [None, {}]:
    for repeat in range(2):
        path = '/tmp/module-target-langflow-0769-native-canary'
        marker = 'native-0769-' + ('none' if frontend is None else 'empty') + '-' + str(repeat)
        native.execute('test', '!', '-e', path)
        effect = 'with open(' + repr(path) + ',"a",encoding="utf-8") as output:\n output.write(' + repr(marker) + ')\n'
        data = {'code': component_source(effect=effect)}
        if frontend is not None:
            data['frontend_node'] = frontend
        status, body = native.http(endpoint, token, data=data)
        assert status == 200, (status, body)
        observed = json.loads(native.execute('python', '-c', 'from pathlib import Path;import json;p=Path(' + repr(path) + ');print(json.dumps(dict(bytes=p.read_text(),uid=p.stat().st_uid,gid=p.stat().st_gid)));p.unlink();assert not p.exists()'))
        count, remainder = divmod(len(observed['bytes']), len(marker))
        assert count == 3 and remainder == 0 and observed['bytes'] == marker*count and observed['uid'] == 1000 and observed['gid'] == 0, observed
        proofs.append({'frontend_node': frontend, 'repeat': repeat, 'marker': marker, 'executions': count, 'observed': observed, 'response': json.loads(body)})
assert snapshot('builtin-after') == baseline
status, body = native.http('/api/v1/flows/', token)
assert status == 200 and json.loads(body) == flows
print(json.dumps({'version': version, 'vendor': vendor, 'mode': mode, 'baseline': baseline,
                  'responses': responses, 'proofs': proofs, 'flow_registry_unchanged': True, 'flows': flows}))
