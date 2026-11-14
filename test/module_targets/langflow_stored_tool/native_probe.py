from pathlib import Path
import ast
import base64
import copy
import hashlib
import importlib.util
import json
import os
import sys

action, tag = sys.argv[1:]
assert action in ['verify', 'health', 'registry', 'cleanup', 'job', 'stage', 'unstage']
version = os.environ['LANGFLOW_STORED_TOOL_VERSION']
root = Path(__file__).parent
os.environ['LANGFLOW_PROFILE'] = 'auth'
spec = importlib.util.spec_from_file_location('native', root.parent/'langflow/native.py')
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
native = module.Native(tag)
state_path = native.artifacts/'langflow-stored-tool-native-state.json'
if action in ['stage', 'unstage']:
    import re
    assert re.fullmatch(r'stage_[0-9_]+', tag)
    state = json.loads(state_path.read_text())
    staged = state.setdefault('staged', {})
    assert native.flows(state['token']) == state['registry']
    previous_registry = state['registry']
    if action == 'stage':
        assert tag not in staged
        request = json.loads((native.artifacts/('preloaded-'+tag+'.json')).read_text())
        encoded = request['payload_base64']
        ast.parse(base64.b64decode(encoded, validate=True).decode('utf-8'))
        data = copy.deepcopy(state['created'][0]['data'])
        template = data['nodes'][0]['data']['node']['template']
        # Existing-flow mode needs pre-existing matching code. Preparing this
        # separate fixture is not payload delivery performed by the owner.
        launch = "__import__('threading').Thread(target=__import__('subprocess').run,args=([__import__('sys').executable,'-c',__import__('base64').b64decode(" + repr(encoded) + ").decode('utf-8')],),kwargs={'stdin':__import__('subprocess').DEVNULL,'stdout':__import__('subprocess').DEVNULL,'stderr':__import__('subprocess').DEVNULL},daemon=True).start()"
        template['tool_code']['value'] = '@(lambda function: (' + launch + ',function)[-1])\ndef module_target_native_tool() -> str:\n return "preloaded"\n'
        status, body = native.http('/api/v1/flows/', state['token'], data=dict(name='Module preloaded payload '+tag,description='Known public flow with independently prepared matching payload',mcp_enabled=False,access_type='PUBLIC',data=data))
        assert status == 201, (status,body)
        created = json.loads(body)
        staged[tag] = dict(id=created['id'],payload=request['payload'],payload_sha256=hashlib.sha256(base64.b64decode(encoded)).hexdigest())
        result = dict(staged=True,flow_id=created['id'],payload=request['payload'],payload_sha256=staged[tag]['payload_sha256'])
    else:
        owned = staged[tag]
        assert native.http('/api/v1/flows/'+owned['id'],state['token'],method='DELETE')[0] == 200
        del staged[tag]
        result = dict(removed=True,flow_id=owned['id'])
    state['registry'] = native.flows(state['token'])
    if action == 'stage':
        assert [row for row in state['registry'] if row['id'] != result['flow_id']] == previous_registry
    else:
        assert state['registry'] == [row for row in previous_registry if row['id'] != result['flow_id']]
    expected = sorted(row['id'] for row in state['created']) + [row['id'] for row in state['baseline']] + [row['id'] for row in staged.values()]
    assert sorted(row['id'] for row in state['registry']) == sorted(expected)
    state_path.write_text(json.dumps(state,indent=2)+'\n')
    print(json.dumps(result))
    sys.exit(0)
if action == 'job':
    import re
    assert re.fullmatch(r'[0-9a-f-]{36}', tag)
    status, body = native.http('/api/v1/build_public_tmp/'+tag+'/events', timeout=30)
    result = dict(status=status)
    if status == 200:
        events = [json.loads(line) for line in body.splitlines() if line.strip()]
        assert events and events[-1]['event'] == 'end', events
        result['events'] = events
    else:
        result['response'] = body.decode()
    print(json.dumps(result))
    sys.exit(0)
if action in ['registry', 'cleanup']:
    state = json.loads(state_path.read_text())
    if action == 'registry':
        assert native.flows(state['token']) == state['registry']
        print(json.dumps(dict(flow_ids=sorted(row['id'] for row in state['registry']))))
    else:
        assert state.get('staged', {}) == {}, 'Preloaded session fixture was not retired'
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
catalog = json.loads((root/'vendor.json').read_text())
expected = catalog['installed'][version]
program = """import hashlib,importlib.metadata as m,importlib.util as u,json,os,pathlib,sys
out=dict(uid=os.getuid(),gid=os.getgid(),python=sys.version.split()[0],versions={name:m.version(name) for name in ['langflow','langflow-base','lfx','mcp']},sources={})
for name in json.loads(sys.argv[1]):
 package,relative=name.split('/',1);base=pathlib.Path(next(iter(u.find_spec(package).submodule_search_locations)));out['sources'][name]=hashlib.sha256((base/relative).read_bytes()).hexdigest()
print(json.dumps(out))"""
vendor=json.loads(native.execute('python','-c',program,json.dumps(list(expected['sources']))))
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
path = '/tmp/module-target-langflow-structured-native'
legacy_version = '1.9.0' if version == '1.10.0' else version
legacy_name = 'lfx/components/tools/python_code_structured_tool.py'
if version == '1.10.0':
    legacy = (root/'legacy_component.py').read_text()
    expected_legacy = catalog['legacy_component']['sha256']
else:
    legacy = native.execute('python','-c',"import importlib.util as u,pathlib;root=pathlib.Path(next(iter(u.find_spec('lfx').submodule_search_locations)));print((root/'components/tools/python_code_structured_tool.py').read_text(),end='')").decode()
    expected_legacy = expected['sources'][legacy_name]
legacy_digest = hashlib.sha256(legacy.encode()).hexdigest()
assert legacy_digest == expected_legacy


def absent():
    native.execute('test', '!', '-e', path)


def canary(marker):
    settings = "__import__('langflow.services.deps',fromlist=['get_settings_service']).get_settings_service()"
    state = "dict(marker=" + repr(marker) + ",pid=__import__('os').getpid(),uid=__import__('os').getuid(),gid=__import__('os').getgid(),builtin_keys=sorted(vars(__import__('builtins'))),auto_login=" + settings + ".auth_settings.AUTO_LOGIN,lazy_load_components=" + settings + ".settings.lazy_load_components,allow_custom_components=getattr(" + settings + ".settings,'allow_custom_components',None),rate_limit_enabled=getattr(" + settings + ".settings,'rate_limit_enabled',None),rate_limit_per_minute=getattr(" + settings + ".settings,'rate_limit_per_minute',None))"
    write = "__import__('pathlib').Path(" + repr(path) + ").open('a').write(__import__('json').dumps(" + state + ")+chr(10))"
    return '@(lambda function: (' + write + ', function)[-1])\ndef module_target_native_tool() -> str:\n return "native"\n'


def proof(marker):
    global backend
    observed = json.loads(native.execute('python', '-c', 'from pathlib import Path;import json;p=Path(' + repr(path) + ');lines=p.read_text().splitlines();assert len(lines)==1,lines;print(lines[0]);assert p.stat().st_uid==1000;p.unlink();assert not p.exists()'))
    assert observed['marker'] == marker and observed['uid'] == 1000 and observed['gid'] == 0
    assert observed['auto_login'] is False and observed['lazy_load_components'] is False
    assert observed['allow_custom_components'] == (None if version == '1.8.4' else True)
    if version == '1.10.0':
        assert observed['rate_limit_enabled'] is True and observed['rate_limit_per_minute'] == 100
    else:
        assert observed['rate_limit_enabled'] is None and observed['rate_limit_per_minute'] is None
    state = {key:value for key,value in observed.items() if key != 'marker'}
    assert backend is None or backend == state
    backend = state
    return observed


def build(flow_id, *, authenticated=False, cookie=True, tag='native'):
    prefix = '/api/v1/build/' if authenticated else '/api/v1/build_public_tmp/'
    headers = {'Cookie': 'client_id=module-target-native-tool-'+tag} if cookie else {}
    status, body = native.http(prefix+flow_id+'/flow', token if authenticated else None, data={}, headers=headers, timeout=30)
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


absent()
status, body = native.http('/api/v1/custom_component', token, data=dict(code=legacy,frontend_node={}), timeout=30)
assert status == 200, (status,body)
component = json.loads(body)
assert component['type'] == 'PythonCodeStructuredTool', component
(native.artifacts/'component-schema.json').write_text(json.dumps(component,indent=2)+'\n')
template = component['data']['template']
values = dict(tool_code=canary('native-stored-tool'),tool_name='module_target_native_tool',tool_description='Native tool execution canary',tool_function='module_target_native_tool',return_direct=False,global_variables=[],_classes='[]',_functions=json.dumps({'module_target_native_tool':{'args':[]}}))
for name,value in values.items():
    assert name in template,(name,list(template))
    template[name]['value']=value
template['tool_function']['options']=['module_target_native_tool']
component['data']['frozen']=False
for output in component['data']['outputs']:
    output['cache']=False
node_id='PythonCodeStructuredTool-native'
flow_data=dict(nodes=[dict(id=node_id,type='genericNode',position=dict(x=0,y=0),data=dict(id=node_id,type=component['type'],node=component['data']))],edges=[])
if state is None:
    assert tag == 'before'
    for access in ['PUBLIC','PRIVATE']:
        status, body = native.http('/api/v1/flows/',token,data=dict(name='Module native tool '+access,description='Stored tool-code boundary control',mcp_enabled=False,access_type=access,data=flow_data))
        assert status==201,(status,body)
        row=json.loads(body);assert row['access_type']==access
        created.append(row)
    state=dict(baseline=baseline,created=created,token=token,registry=native.flows(token))
    state_path.write_text(json.dumps(state,indent=2)+'\n')
else:
    assert native.flows(token)==state['registry']
registry=native.flows(token)
absent()
for case,flow_id,cookie,expected_status in [('missing-cookie',created[0]['id'],False,400),('private-flow',created[1]['id'],True,403),('unknown-flow','00000000-0000-4000-8000-000000000001',True,403)]:
    status,value=build(flow_id,cookie=cookie,tag=case)
    assert status==expected_status,(case,status,value)
    absent();proofs.append(dict(case=case,status=status,response=value))
for repeat in range(2):
    status,value=build(created[0]['id'],tag='public-'+str(repeat))
    assert status==(400 if version=='1.10.0' else 200),(status,value)
    if version=='1.10.0':
        absent();proofs.append(dict(case='public-stored-tool',repeat=repeat,status=status,response=value))
    else:
        observed=proof('native-stored-tool');proofs.append(dict(case='public-stored-tool',repeat=repeat,status=status,proof=observed,build=value))
for repeat in range(2):
    status,value=build(created[1]['id'],authenticated=True,tag='auth-'+str(repeat))
    assert status==200,(status,value)
    observed=proof('native-stored-tool');proofs.append(dict(case='authenticated-stored-tool',repeat=repeat,status=status,proof=observed,build=value))
assert native.flows(token)==registry
for row in proofs:
    row.pop('build',None)
print(json.dumps(dict(version=version_document,vendor=vendor,legacy_source_version=legacy_version,legacy_source_sha256=legacy_digest,legacy_imported_from_installed_code=version!='1.10.0',proofs=proofs,backend=backend,full_registry_unchanged=True,flow_ids=sorted(row['id'] for row in state['registry']),public_id=created[0]['id'],private_id=created[1]['id'],known_marker_path=path,baseline_flow_ids=sorted(row['id'] for row in baseline))))
