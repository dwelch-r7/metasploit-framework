"""Genuine custom-component controls independent of the Framework owner."""
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
status, body = native.http('/api/v1/version')
version = json.loads(body)
assert status == 200 and version['version'] == '1.10.0' and version['package'] == 'Langflow'
if action == 'health':
    print(json.dumps(version))
    sys.exit(0)

program = """import importlib.metadata as m,importlib.util as u,pathlib,hashlib,json,os,sys
from lfx.services.settings.base import Settings
out=dict(uid=os.getuid(),gid=os.getgid(),python=sys.version.split()[0],versions={n:m.version(n) for n in ['langflow','langflow-base','lfx','mcp']})
sources={}
for package,relative in [('langflow','api/v1/endpoints.py'),('lfx','services/settings/base.py'),('lfx','custom/utils.py'),('lfx','custom/validate.py')]:
 root=pathlib.Path(next(iter(u.find_spec(package).submodule_search_locations)))
 sources[package+'/'+relative]=hashlib.sha256((root/relative).read_bytes()).hexdigest()
print(json.dumps(dict(installed=out,sources=sources,allow_custom_components=Settings().allow_custom_components,rate_limit_enabled=Settings().rate_limit_enabled,rate_limit_per_minute=Settings().rate_limit_per_minute)))"""
observed = json.loads(native.execute('python', '-c', program))
expected = json.loads(Path(__file__).with_name('vendor.json').read_text())
assert observed['installed'] == expected['installed']
assert observed['sources'] == expected['sources']
protected = os.environ.get('LANGFLOW_CUSTOM_POLICY', 'true') == 'false'
assert observed['allow_custom_components'] is (not protected)
assert observed['rate_limit_enabled'] is True and observed['rate_limit_per_minute'] == 100


def component(effect=None, decorator=False):
    lines = [
        'from langflow.custom import Component',
        'from langflow.io import Output, MessageTextInput',
        'from langflow.schema import Data',
        '_fired = [False]',
        'class NativeCanary(Component):',
        "    display_name = 'Native canary'",
        "    name = 'NativeCanary'",
        "    inputs = [MessageTextInput(display_name='Native input', name='input_value')]",
        "    outputs = [Output(display_name='Native output', name='out', method='native_output')]",
    ]
    if effect and not decorator:
        lines.append('    native_effect = ' + effect)
    if effect and decorator:
        lines.append('    @(lambda fn: (_fired[0] or (_fired.__setitem__(0, True), exec(' + repr(effect) + ')), fn)[-1])')
    lines += ['    def native_output(self) -> Data:', "        return Data(data={'output': 'native'})"]
    return dict(code='\n'.join(lines), frontend_node={})


benign = component()
assert native.http('/api/v1/custom_component', data=benign)[0] == 403
assert native.http('/api/v1/login', form={
    'username': 'module-target-admin', 'password': 'module-target-incorrect'})[0] == 401
token = native.token()
# Exercise more than the default five logins from one client, proving that the
# supported test-profile allowance is active in the running backend.
for attempt in range(6):
    status, body = native.http('/api/v1/login', form={
        'username': 'module-target-admin', 'password': 'module-target-native-password'})
    assert status == 200 and json.loads(body)['access_token']
flows = native.flows(token)
status, body = native.http('/api/v1/custom_component', token, data=benign)
assert status == (403 if protected else 200), (status, body)
if not protected:
    assert json.loads(body)['type'] == 'NativeCanary'
proofs = []
for family, count in [('class_body', 6), ('decorator', 3)]:
    path = '/tmp/module-target-langflow-custom-native-' + family
    marker = 'langflow-custom-' + family + '\n'
    native.execute('python', '-c', 'from pathlib import Path; assert not Path(' + repr(path) + ').exists()')
    effect = '__import__(\'pathlib\').Path(' + repr(path) + ').open(\'ab\').write(' + repr(marker.encode()) + ')'
    status, body = native.http('/api/v1/custom_component', token, data=component(effect, family == 'decorator'))
    if protected:
        assert status == 403 and json.loads(body)['detail'] == 'Custom component creation is disabled'
        native.execute('python', '-c', 'from pathlib import Path; assert not Path(' + repr(path) + ').exists()')
        proofs.append(dict(family=family, status=403, path_absent=True))
        continue
    assert status == 200 and json.loads(body)['type'] == 'NativeCanary'
    proof = json.loads(native.execute('python', '-c',
        'from pathlib import Path; import json; p=Path(' + repr(path) + '); '
        'print(json.dumps(dict(bytes=p.read_text(),uid=p.stat().st_uid,gid=p.stat().st_gid))); p.unlink(); assert not p.exists()'))
    assert proof == dict(bytes=marker * count, uid=1000, gid=0), proof
    proofs.append(dict(family=family, writes=count, proof=proof))
backend_state = None
if not protected:
    path = '/tmp/module-target-langflow-custom-native-builtins'
    native.execute('python', '-c', 'from pathlib import Path; assert not Path(' + repr(path) + ').exists()')
    effect = '__import__(\'pathlib\').Path(' + repr(path) + ').write_text(__import__(\'json\').dumps(dict(pid=__import__(\'os\').getpid(), builtin_keys=sorted(__import__(\'builtins\').__dict__))))'
    status, body = native.http('/api/v1/custom_component', token, data=component(effect))
    assert status == 200
    backend_state = json.loads(native.execute('python', '-c', 'from pathlib import Path; p=Path(' + repr(path) + '); print(p.read_text()); p.unlink(); assert not p.exists()'))
assert native.flows(token) == flows
print(json.dumps(dict(vendor=observed, flow_ids=sorted(row['id'] for row in flows), proofs=proofs, backend_state=backend_state)))
