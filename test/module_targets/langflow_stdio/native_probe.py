"""Real SDK, registry, tenant and execution controls without Framework calls."""
from pathlib import Path
import base64
import hashlib
import importlib.util
import json
import os
import re
import sys
import urllib.parse

spec = importlib.util.spec_from_file_location('langflow_native', Path(__file__).parents[1] / 'langflow/native.py')
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
action, tag = sys.argv[1:]
assert action in ('verify', 'health', 'registry') and re.fullmatch(r'[a-z0-9_-]+', tag)
os.environ['LANGFLOW_PROFILE'] = 'auth'
native = module.Native(tag)
version = os.environ.get('LANGFLOW_STDIO_VERSION', '1.8.4')
status, body = native.http('/api/v1/version')
observed_version = json.loads(body)
assert status == 200 and observed_version.get('version') == version and observed_version.get('package') == 'Langflow', observed_version
if action == 'health':
    print(json.dumps(observed_version))
    sys.exit(0)

state_path = native.artifacts / 'langflow-stdio-native-state.json'
username = 'module-target-operator'
password = 'module-target-operator-password'


def api(path='', token=None, **kwargs):
    status, body = native.http('/api/v2/mcp/servers' + path, token, timeout=45, **kwargs)
    return status, json.loads(body)


def registry(token):
    status, rows = api('?action_count=false', token)
    assert status == 200 and isinstance(rows, list), (status, rows)
    result = {}
    for row in rows:
        status, config = api('/' + urllib.parse.quote(row['name'], safe=''), token)
        assert status == 200 and isinstance(config, dict), (status, config)
        result[row['name']] = config
    return result


def registry_proof(state):
    actual = dict(root=registry(state['root_token']), operator=registry(state['operator_token']))
    (native.artifacts / ('registry-' + tag + '.json')).write_text(json.dumps(actual, indent=2) + '\n')
    assert actual == state['registries'], actual
    return {key: dict(names=sorted(value), sha256=hashlib.sha256(json.dumps(value, sort_keys=True).encode()).hexdigest())
            for key, value in actual.items()}


if action == 'registry':
    print(json.dumps(registry_proof(json.loads(state_path.read_text()))))
    sys.exit(0)

expected = json.loads(Path(__file__).with_name('vendor.json').read_text())['installed'][version]
program = """import importlib.metadata as m,importlib.util,pathlib,hashlib,json,os,sys
from lfx.services.settings.base import Settings
s=Settings()
sources={}
for name in json.loads(sys.argv[1]):
 package,relative=name.split('/',1)
 root=pathlib.Path(next(iter(importlib.util.find_spec(package).submodule_search_locations)))
 sources[name]=hashlib.sha256((root/relative).read_bytes()).hexdigest()
print(json.dumps(dict(installed=dict(uid=os.getuid(),gid=os.getgid(),python=sys.version.split()[0],versions={n:m.version(n) for n in ['langflow','langflow-base','lfx','mcp']}),settings={key:getattr(s,key,None) for key in ['mcp_server_timeout','rate_limit_enabled','rate_limit_per_minute','add_projects_to_mcp_servers']},sources=sources)))"""
observed = json.loads(native.execute('python', '-c', program, json.dumps(list(expected['sources']))))
assert observed == expected, observed
sdk_path = '/opt/module-target-native-stdio-server.py'
sdk_hash = native.execute('python', '-c', 'from pathlib import Path; import hashlib; print(hashlib.sha256(Path(' + repr(sdk_path) + ').read_bytes()).hexdigest())').decode().strip()
assert sdk_hash == json.loads(Path(__file__).with_name('vendor.json').read_text())['sdk_source_sha256']

if state_path.exists():
    state = json.loads(state_path.read_text())
    registry_proof(state)
else:
    assert native.http('/api/v2/mcp/servers?action_count=false')[0] == 403
    root_token = native.token()
    root_registry = registry(root_token)
    root_control = 'module-target-other-user-control'
    assert root_control not in root_registry
    definition = dict(command='python3', args=[sdk_path])
    assert api('/' + root_control, root_token, data=definition) == (200, definition)
    root_registry[root_control] = definition
    status, body = native.http('/api/v1/users/', root_token, data=dict(username=username, password=password))
    user = json.loads(body)
    assert status == 201 and user['username'] == username and user['is_superuser'] is False, (status, user)
    if not user['is_active']:
        status, body = native.http('/api/v1/users/' + user['id'], root_token, method='PATCH', data=dict(is_active=True))
        assert status == 200 and json.loads(body)['is_active'] is True
    status, body = native.http('/api/v1/login', form=dict(username=username, password=password))
    assert status == 200
    operator_token = json.loads(body)['access_token']
    operator_registry = registry(operator_token)
    assert 'module-target-native-control' not in operator_registry
    definition = dict(command='python3', args=[sdk_path])
    assert api('/module-target-native-control', operator_token, data=definition) == (200, definition)
    operator_registry['module-target-native-control'] = definition
    state = dict(root_token=root_token, operator_token=operator_token,
                 registries=dict(root=root_registry, operator=operator_registry), operator_id=user['id'])
    state_path.write_text(json.dumps(state, indent=2) + '\n')

token = state['operator_token']
status, body = native.http('/api/v1/users/whoami', token)
identity = json.loads(body)
assert status == 200 and identity['id'] == state['operator_id'] and identity['is_superuser'] is False and identity['is_active'] is True
assert native.http('/api/v1/login', form=dict(username=username, password='module-target-incorrect'))[0] == 401
assert api('/module-target-native-control', token) == (200, dict(command='python3', args=[sdk_path]))
status, result = api('?action_count=true', token)
assert status == 200 and next(row for row in result if row['name'] == 'module-target-native-control') == dict(name='module-target-native-control', mode='stdio', toolsCount=1), result

proofs = []
if version == '1.9.0':
    status, result = api('/module-target-native-denied-flag', token, data=dict(command='python3', args=['-c', 'pass']))
    assert status == 422 and any("Flag -c or /c is only allowed with shell wrappers" in error['msg'] for error in result['detail']), (status, result)
    proofs.append(dict(family='inline-flag', blocked=True))
for repeat in range(2):
    name = 'module-target-native-canary-' + str(repeat)
    path = '/tmp/module-target-stdio-native-' + tag + '-' + str(repeat)
    marker = 'module-target-stdio-native-' + str(repeat) + '\n'
    native.execute('python', '-c', 'from pathlib import Path; assert not Path(' + repr(path) + ').exists()')
    effect = '__import__(\'pathlib\').Path(' + repr(path) + ').open(\'ab\').write(' + repr(marker.encode()) + ')'
    encoded = base64.b64encode(effect.encode()).decode()
    code = "exec(__import__('base64').b64decode('" + encoded + "'))"
    status, result = api('/' + name, token, data=dict(command='python3', args=['-c', code]))
    if version == '1.9.0':
        assert status == 422 and result['detail'], (status, result)
        native.execute('python', '-c', 'from pathlib import Path; assert not Path(' + repr(path) + ').exists()')
        proofs.append(dict(family='encoded-canary', repeat=repeat, blocked=True))
        continue
    assert status == 200, (status, result)
    try:
        native.execute('python', '-c', 'from pathlib import Path; assert not Path(' + repr(path) + ').exists()')
        for trigger in range(2):
            status, result = api('?action_count=true', token)
            assert status == 200
            proof = json.loads(native.execute('python', '-c', 'from pathlib import Path; import json; p=Path(' + repr(path) + '); print(json.dumps(dict(bytes=p.read_text(),uid=p.stat().st_uid,gid=p.stat().st_gid)))'))
            assert proof == dict(bytes=marker * (trigger + 1), uid=1000, gid=0), proof
        proofs.append(dict(family='encoded-canary', repeat=repeat, blocked=False, writes_per_listing=1))
    finally:
        assert api('/' + name, token, method='DELETE') == (200, None)
        native.execute('rm', '-f', '--', path)
print(json.dumps(dict(vendor=observed, operator_is_superuser=False, operator_is_active=True,
                     registry=registry_proof(state), proofs=proofs)))
