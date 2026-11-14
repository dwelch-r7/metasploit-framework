"""Independent genuine legacy authentication and exact execution controls."""
import importlib.util
import json
import os
from pathlib import Path
import sys

action, tag = sys.argv[1:]
assert action in ('verify', 'health')
mode = os.environ['LANGFLOW_LEGACY_PROFILE']
os.environ['LANGFLOW_PROFILE'] = 'auth' if mode == 'protected' else 'auto'
spec = importlib.util.spec_from_file_location('native', Path(__file__).parents[1] / 'langflow/native.py')
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
native = module.Native(tag)
status, body = native.http('/api/v1/version')
version = json.loads(body)
assert status == 200 and version['version'] == '1.4.2' and version['package'] == 'Langflow', (status, version)
if action == 'health':
    print(json.dumps(version))
    sys.exit(0)
vendor = json.loads(native.execute('python', '-c', Path(__file__).with_name('source_probe.py').read_text()))
vendor.pop('texts')
expected = json.loads(Path(__file__).with_name('vendor.json').read_text())['installed']
assert vendor == expected, vendor
benign = {'code': 'def module_target_benign(value=1):\n return value\n'}
anonymous = native.http('/api/v1/validate/code', data=benign)
assert anonymous[0] == (403 if mode == 'protected' else 200), anonymous
assert native.http('/api/v1/validate/code', 'module-target-invalid', data=benign)[0] == 401
token = None
if mode == 'protected':
    status, body = native.http('/api/v1/login', form={'username': 'module-target-admin', 'password': 'module-target-native-password'})
    assert status == 200, (status, body)
    token = json.loads(body)['access_token']
    assert native.http('/api/v1/validate/code', token, data=benign)[0] == 200
setting_path = '/tmp/module-target-langflow-0768-settings'
native.execute('test', '!', '-e', setting_path)
expression = "__import__('json').dumps({'auto_login':__import__('langflow.services.deps',fromlist=['get_settings_service']).get_settings_service().auth_settings.AUTO_LOGIN,'lazy_load_components':__import__('langflow.services.deps',fromlist=['get_settings_service']).get_settings_service().settings.lazy_load_components})"
code = 'def module_target_settings(value=__import__("pathlib").Path(' + repr(setting_path) + ').write_text(' + expression + ')):\n pass\n'
assert native.http('/api/v1/validate/code', token, data={'code': code})[0] == 200
settings = json.loads(native.execute('python', '-c', 'from pathlib import Path;p=Path(' + repr(setting_path) + ');print(p.read_text());assert p.stat().st_uid==1000;p.unlink();assert not p.exists()'))
assert settings == {'auto_login': mode != 'protected', 'lazy_load_components': False}, settings
status, body = native.http('/api/v1/flows/', token)
assert status == 200, (status, body)
flows = json.loads(body)
proofs = []
for family in ['default', 'decorator']:
    for repeat in range(2):
        path = '/tmp/module-target-langflow-0768-native-' + family
        marker = 'native-0768-' + family + '-' + str(repeat)
        native.execute('test', '!', '-e', path)
        effect = 'with open(' + repr(path) + ',"a",encoding="utf-8") as output:\n output.write(' + repr(marker) + ')\n'
        code = ('def module_target_default(value=exec(' + repr(effect) + ')):\n return value\n' if family == 'default'
                else '@exec(' + repr(effect) + ')\ndef module_target_decorator():\n pass\n')
        status, body = native.http('/api/v1/validate/code', token, data={'code': code})
        assert status == 200, (status, body)
        observed = json.loads(native.execute('python', '-c', 'from pathlib import Path;import json;p=Path(' + repr(path) + ');print(json.dumps(dict(bytes=p.read_text(),uid=p.stat().st_uid,gid=p.stat().st_gid)));p.unlink();assert not p.exists()'))
        assert observed == dict(bytes=marker, uid=1000, gid=0), observed
        proofs.append({'family': family, 'repeat': repeat, 'observed': observed, 'response': json.loads(body)})
status, body = native.http('/api/v1/flows/', token)
assert status == 200 and json.loads(body) == flows
print(json.dumps({'version': version, 'vendor': vendor, 'mode': mode, 'settings': settings,
                  'proofs': proofs, 'flow_registry_unchanged': True, 'flows': flows}))
