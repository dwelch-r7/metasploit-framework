"""Saved-flow controls against the genuine backend, without Framework calls."""
from pathlib import Path
import copy
import hashlib
import importlib.util
import json
import os
import re
import sys

spec = importlib.util.spec_from_file_location('langflow_native', Path(__file__).parents[1] / 'langflow/native.py')
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
action, tag = sys.argv[1:]
assert action in ('verify', 'health', 'registry') and re.fullmatch(r'[a-z0-9_-]+', tag)
os.environ['LANGFLOW_PROFILE'] = 'auth'
native = module.Native(tag)
state_path = native.artifacts / 'langflow-flow-native-state.json'
if action == 'registry':
    state = json.loads(state_path.read_text())
    ids = sorted(row['id'] for row in native.flows(state['token']))
    assert ids == state['flow_ids'], ids
    print(json.dumps(dict(flow_ids=ids)))
    sys.exit(0)
status, body = native.http('/api/v1/version')
version = json.loads(body)
assert status == 200 and version['version'] == '1.10.0' and version['package'] == 'Langflow'
if action == 'health':
    print(json.dumps(version))
    sys.exit(0)

base = Path(__file__).parent
expected = json.loads((base.parent / 'langflow_custom/vendor.json').read_text())
flow_vendor = json.loads((base / 'vendor.json').read_text())
expected['sources'].update(flow_vendor['sources'])
program = """import importlib.metadata as m,importlib.util as u,pathlib,hashlib,json,os,sys
from lfx.services.settings.base import Settings
out=dict(uid=os.getuid(),gid=os.getgid(),python=sys.version.split()[0],versions={n:m.version(n) for n in ['langflow','langflow-base','lfx','mcp']})
sources={}
for name in json.loads(sys.argv[1]):
 package,relative=name.split('/',1)
 root=pathlib.Path(next(iter(u.find_spec(package).submodule_search_locations)))
 sources[name]=hashlib.sha256((root/relative).read_bytes()).hexdigest()
s=Settings()
print(json.dumps(dict(installed=out,sources=sources,allow_custom_components=s.allow_custom_components,rate_limit_enabled=s.rate_limit_enabled,rate_limit_per_minute=s.rate_limit_per_minute)))"""
observed = json.loads(native.execute('python', '-c', program, json.dumps(list(expected['sources']))))
protected = os.environ.get('LANGFLOW_FLOW_POLICY', 'false') == 'false'
assert observed['installed'] == expected['installed'] and observed['sources'] == expected['sources'], observed
assert observed['allow_custom_components'] is (not protected)
assert observed['rate_limit_enabled'] is True and observed['rate_limit_per_minute'] == 100
blueprint_bytes = (base / 'benign_component.json').read_bytes()
assert hashlib.sha256(blueprint_bytes).hexdigest() == flow_vendor['blueprint_sha256']
blueprint = json.loads(blueprint_bytes)
code = blueprint['data']['template']['code']['value']
assert native.http('/api/v1/flows/')[0] == 403
assert native.http('/api/v1/login', form={'username': 'module-target-admin', 'password': 'module-target-incorrect'})[0] == 401
token = native.token()
for attempt in range(6):
    status, body = native.http('/api/v1/login', form={'username': 'module-target-admin', 'password': 'module-target-native-password'})
    assert status == 200 and json.loads(body)['access_token']
baseline = sorted(row['id'] for row in native.flows(token))
if state_path.exists():
    assert baseline == json.loads(state_path.read_text())['flow_ids']
else:
    state_path.write_text(json.dumps(dict(token=token, flow_ids=baseline)) + '\n')
status, body = native.http('/api/v1/custom_component', token, data=dict(code=code, frontend_node={}))
assert status == (403 if protected else 200), (status, body)
if protected:
    assert json.loads(body) == {'detail': 'Custom component creation is disabled'}


def build(flow_id):
    status, body = native.http('/api/v1/build/' + flow_id + '/flow', token, data={})
    if status != 200:
        return status, [json.loads(body)]
    job_id = json.loads(body)['job_id']
    status, body = native.http('/api/v1/build/' + job_id + '/events', token)
    assert status == 200
    return status, [json.loads(line) for line in body.splitlines() if line.strip()]


proofs = []
backend_state = None
for family, blank_type in [('typed', False), ('empty', True), ('empty-repeat', True)]:
    path = '/tmp/module-target-langflow-flow-native-' + tag + '-' + family
    marker = 'module-target-langflow-flow-native-' + family + '\n'
    native.execute('python', '-c', 'from pathlib import Path; assert not Path(' + repr(path) + ').exists()')
    effect = "p=__import__('pathlib').Path(" + repr(path) + "); p.open('a').write(__import__('json').dumps(dict(marker=" + repr(marker) + ",pid=__import__('os').getpid(),builtin_keys=sorted(__import__('builtins').__dict__)))+'\\n')"
    component = copy.deepcopy(blueprint['data'])
    decorator = '    @(lambda fn: (_fired[0] or (_fired.__setitem__(0, True), exec(' + repr(effect) + ')), fn)[-1])\n'
    component['template']['code']['value'] = code.replace('    def native_output', decorator + '    def native_output')
    node_id = 'NativeFlowCanary-' + tag + '-' + family
    flow = dict(name='Module native flow ' + family, description='Native calibration', mcp_enabled=False, access_type='PRIVATE',
                data=dict(nodes=[dict(id=node_id, type='genericNode', position=dict(x=0,y=0),
                                     data=dict(id=node_id, type='' if blank_type else blueprint['type'], node=component))], edges=[]))
    status, body = native.http('/api/v1/flows/', token, data=flow)
    assert status == 201, (status, body)
    flow_id = json.loads(body)['id']
    try:
        native.execute('python', '-c', 'from pathlib import Path; assert not Path(' + repr(path) + ').exists()')
        status, events = build(flow_id)
        if protected and not blank_type:
            assert status == 400 and events == [{'detail': 'Flow build blocked: custom components are not allowed: Native flow canary (' + node_id + ')'}], (status, events)
            native.execute('python', '-c', 'from pathlib import Path; assert not Path(' + repr(path) + ').exists()')
            proofs.append(dict(family=family, blocked=True, stage='build', status=status))
            continue
        assert status == 200 and events[-1]['event'] == 'end', events
        vertices = [event['data']['build_data'] for event in events if event['event'] == 'end_vertex']
        assert len(vertices) == 1 and vertices[0]['valid'] is True, events
        assert vertices[0]['data']['outputs']['out']['message'] == {'output': 'module-target-native-flow-output'}, events
        proof = json.loads(native.execute('python', '-c', 'from pathlib import Path; import json; p=Path(' + repr(path) + '); lines=p.read_text().splitlines(); assert len(lines)==1, lines; print(json.dumps(dict(data=json.loads(lines[0]),uid=p.stat().st_uid))); p.unlink(); assert not p.exists()'))
        assert proof['uid'] == 1000 and proof['data']['marker'] == marker, proof
        state = {key: proof['data'][key] for key in ('pid', 'builtin_keys')}
        assert backend_state is None or state == backend_state
        backend_state = state
        proofs.append(dict(family=family, blocked=False, uid=1000, output='module-target-native-flow-output'))
    finally:
        assert native.http('/api/v1/flows/' + flow_id, token, method='DELETE')[0] == 200
assert sorted(row['id'] for row in native.flows(token)) == baseline
print(json.dumps(dict(vendor=observed, flow_ids=baseline, proofs=proofs, backend_state=backend_state)))
