"""Real authenticated validation and exact file controls independent of the owner."""
from pathlib import Path
import importlib.util
import json
import os
import sys

spec = importlib.util.spec_from_file_location('langflow_native', Path(__file__).parents[1] / 'langflow/native.py')
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
action, tag = sys.argv[1:]
assert action in ('verify', 'health')
os.environ['LANGFLOW_PROFILE'] = 'auth'
native = module.Native(tag)
if action == 'health':
    status, body = native.http('/api/v1/version')
    version = json.loads(body)
    assert status == 200 and version['version'] == '1.8.4' and version['package'] == 'Langflow'
    print(json.dumps(version))
    sys.exit(0)
vendor = native.vendor()
status, body = native.http('/api/v1/version')
assert status == 200 and json.loads(body)['version'] == '1.8.4'
benign = {'code': 'def module_target_benign(value=1):\n    return value\n'}
assert native.http('/api/v1/validate/code', data=benign)[0] == 403
assert native.http('/api/v1/login', form={
    'username': 'module-target-admin', 'password': 'module-target-incorrect'})[0] == 401
token = native.token()
flows = native.flows(token)
assert native.http('/api/v1/validate/code', token, data=benign)[0] == 200
proofs = []
for family in ['default', 'decorator']:
    path = '/tmp/module-target-langflow-native-' + family
    marker = 'langflow-native-' + family
    native.execute('python', '-c', 'from pathlib import Path; assert not Path(' + repr(path) + ').exists()')
    effect = '__import__(\'pathlib\').Path(' + repr(path) + ').write_text(' + repr(marker) + ')'
    code = ('def module_target_default(value=' + effect + '):\n    return value\n' if family == 'default'
            else '@exec(' + repr(effect) + ')\ndef module_target_decorator():\n    pass\n')
    assert native.http('/api/v1/validate/code', token, data={'code': code})[0] == 200
    observed = json.loads(native.execute('python', '-c',
        'from pathlib import Path; import json; p=Path(' + repr(path) + '); '
        'print(json.dumps(dict(bytes=p.read_text(),uid=p.stat().st_uid,gid=p.stat().st_gid))); '
        'p.unlink(); assert not p.exists()'))
    assert observed == dict(bytes=marker, uid=1000, gid=0)
    proofs.append(observed)
assert native.flows(token) == flows
source = native.execute('python', '-c',
    "import importlib.util,pathlib,hashlib,json; out={}; "
    "files=[('langflow','api/v1/validate.py'),('lfx','custom/validate.py')]; "
    "exec('for package,relative in files:\\n root=pathlib.Path(next(iter(importlib.util.find_spec(package).submodule_search_locations))); out[package+\"/\"+relative]=hashlib.sha256((root/relative).read_bytes()).hexdigest()'); "
    "print(json.dumps(out))")
sources = json.loads(source)
expected = json.loads(Path(__file__).with_name('vendor.json').read_text())
assert sources == expected['validation_sources'], sources
print(json.dumps(dict(vendor=vendor, validation_sources=sources, flow_ids=sorted(row['id'] for row in flows), proofs=proofs)))
