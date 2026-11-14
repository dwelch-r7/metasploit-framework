"""Independent genuine login and exact-command controls for Langflow validation."""
from pathlib import Path
import hashlib
import importlib.util
import json
import os
import sys

action, tag = sys.argv[1:]
assert action in ('verify', 'health')
phase = os.environ['LANGFLOW_VALIDATE_AUTH']
expected_version = os.environ.get('LANGFLOW_VALIDATE_VERSION', '1.7.3')
os.environ['LANGFLOW_PROFILE'] = 'auth' if phase == 'auth' else 'auto'
spec = importlib.util.spec_from_file_location('native', Path(__file__).parents[1] / 'langflow/native.py')
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
native = module.Native(tag)
status, body = native.http('/api/v1/version')
version = json.loads(body)
assert status == 200 and version['version'] == expected_version and version['package'] == 'Langflow', (status, version)
if action == 'health':
    print(json.dumps(version))
    sys.exit(0)
program = '''import importlib.metadata as m,importlib.util,pathlib,hashlib,json,os,sys
out={'uid':os.getuid(),'gid':os.getgid(),'python':sys.version.split()[0],'versions':{n:m.version(n) for n in ['langflow','langflow-base','lfx','mcp']},'sources':{},'texts':{}}
for package,relative in [('langflow','api/v1/validate.py'),('lfx','custom/validate.py'),('langflow','services/auth/utils.py'),('langflow','api/v1/login.py'),('lfx','services/settings/auth.py'),('lfx','services/settings/constants.py'),('lfx','services/settings/base.py')]:
 root=pathlib.Path(next(iter(importlib.util.find_spec(package).submodule_search_locations)));p=root/relative
 if p.exists():out['sources'][package+'/'+relative]=hashlib.sha256(p.read_bytes()).hexdigest();out['texts'][package+'/'+relative]=p.read_text()
print(json.dumps(out))'''
vendor = json.loads(native.execute('python', '-c', program))
vendor.pop('texts')
expected = json.loads(Path(__file__).with_name('vendor.json').read_text())['installed'][expected_version]
assert vendor == expected, vendor
assert vendor['uid'] == 1000 and vendor['gid'] == 0 and vendor['versions']['langflow'] == expected_version
username, password = ('langflow', 'langflow') if phase == 'auto' else ('module-target-admin', 'module-target-native-password')
benign = {'code': 'def module_target_benign(value=1):\n    return value\n'}
anonymous = native.http('/api/v1/validate/code', data=benign)
assert anonymous[0] == 403, anonymous
wrong = native.http('/api/v1/login', form={'username': username, 'password': 'module-target-incorrect'})
assert wrong[0] == 401, wrong
status, body = native.http('/api/v1/auto_login')
assert status == (200 if phase == 'auto' else (400 if expected_version == '1.7.3' else 403)), (status, body)
auto_token = json.loads(body).get('access_token') if status == 200 else None
status, body = native.http('/api/v1/login', form={'username': username, 'password': password})
assert status == 200, (status, body)
explicit_token = json.loads(body)['access_token']
token = auto_token or explicit_token
assert native.http('/api/v1/validate/code', token, data=benign)[0] == 200
setting_path = '/tmp/module-target-langflow-0770-setting'
native.execute('test', '!', '-e', setting_path)
setting = "__import__('langflow.services.deps',fromlist=['get_settings_service']).get_settings_service().settings.lazy_load_components"
code = 'def module_target_setting(value=__import__("pathlib").Path(' + repr(setting_path) + ').write_text(str(' + setting + '))):\n pass\n'
assert native.http('/api/v1/validate/code', token, data={'code': code})[0] == 200
observed_setting = native.execute('python', '-c', 'from pathlib import Path;p=Path(' + repr(setting_path) + ');print(p.read_text(),end="");assert p.stat().st_uid==1000;p.unlink();assert not p.exists()').decode()
assert observed_setting == 'True', observed_setting
flows = native.flows(token)
proofs = []
for mode, current_token in [('explicit', explicit_token)] + ([('auto', auto_token)] if auto_token else []):
    for repeat in range(2):
        path = '/tmp/module-target-langflow-0770-native-' + mode
        marker = 'native-0770-' + mode + '-' + str(repeat)
        native.execute('test', '!', '-e', path)
        command = 'printf %s ' + marker + ' >> ' + path
        code = '''def module_target_execute(
 _=(lambda result: (_ for _ in ()).throw(Exception(f"{result.stdout}{result.stderr}")))(
  __import__('subprocess').run(%s, shell=True, capture_output=True, text=True))
):
 pass
''' % repr(command)
        status, response = native.http('/api/v1/validate/code', current_token, data={'code': code})
        assert status == 200, (status, response)
        observed = json.loads(native.execute('python', '-c', 'from pathlib import Path;import json;p=Path(' + repr(path) + ');print(json.dumps(dict(bytes=p.read_text(),uid=p.stat().st_uid,gid=p.stat().st_gid)));p.unlink();assert not p.exists()'))
        assert observed == dict(bytes=marker, uid=1000, gid=0), observed
        proofs.append(dict(mode=mode, repeat=repeat, observed=observed, response=json.loads(response)))
assert native.flows(token) == flows
print(json.dumps(dict(version=version, vendor=vendor, phase=phase, runtime_settings={'lazy_load_components': True}, proofs=proofs, flow_ids=sorted(row['id'] for row in flows))))
