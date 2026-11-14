"""Genuine n8n controls, fixture account data and complete workflow preservation."""
from pathlib import Path
import base64
import hashlib
from http.cookiejar import CookieJar
from http.cookies import SimpleCookie
import json
import os
import subprocess
import sys
import urllib.error
import urllib.request

action,tag=sys.argv[1:];assert action in ['before','after','registry','seed','token']
runtime=json.loads(Path(os.environ['MODULE_TARGET_RUNTIME']).read_text());artifacts=Path(runtime['artifacts']);root=Path(__file__).parent;version=os.environ.get('N8N_TARGET_VERSION','1.120.0');state_path=artifacts/'ni8mare-state.json';journal=[]
endpoint=runtime['endpoints']['target'];base='http://'+endpoint['host']+':'+str(endpoint['port']);jar=CookieJar();client=urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar));plain=urllib.request.build_opener();cookies={};active_cookie=None
def save():
 (artifacts/('native-'+action+'-'+tag+'-'+str(os.getpid())+'.json')).write_text(json.dumps(journal,indent=2)+'\n')
def command(args,data=None):
 argv=runtime['compose']+args;r=subprocess.run(argv,input=data,capture_output=True,timeout=60);journal.append(dict(argv=argv,actual_exit=r.returncode,stdout_base64=base64.b64encode(r.stdout).decode(),stderr_base64=base64.b64encode(r.stderr).decode()));save();assert r.returncode==0,r.stderr.decode();return r.stdout
def node(program,value=None):
 return json.loads(command(['exec','-T','target','node','-e',program],json.dumps(value).encode()if value is not None else None))
def http(path,method='GET',data=None,headers=None,anonymous=False):
 headers=dict(headers or {});body=None
 if not anonymous and active_cookie:headers.setdefault('Cookie','n8n-auth='+active_cookie)
 if data is not None:body=json.dumps(data).encode();headers['Content-Type']='application/json'
 request=urllib.request.Request(base+path,data=body,method=method,headers=headers)
 try:response=(plain if anonymous else client).open(request,timeout=15)
 except urllib.error.HTTPError as error:response=error
 payload=response.read();response.close();journal.append(dict(path=path,method=method,data=data,anonymous=anonymous,status=response.status,headers=dict(response.headers),body_base64=base64.b64encode(payload).decode()));save();return response.status,payload
def login(email):
 global active_cookie
 jar.clear();active_cookie=cookies[email];status,body=http('/rest/login');assert status==200,(status,body);user=json.loads(body)['data'];assert user['email']==email;return user
def registry():
 status,body=http('/rest/workflows');assert status==200;rows=json.loads(body)['data'];result=[]
 for row in rows:
  code,payload=http('/rest/workflows/'+row['id']);assert code==200;result.append(json.loads(payload)['data'])
 result=sorted(result,key=lambda value:value['id'])
 global_ids=node("const{DatabaseSync}=require('node:sqlite');const db=new DatabaseSync('/home/node/.n8n/database.sqlite',{readOnly:true});const ids=db.prepare('SELECT id FROM workflow_entity ORDER BY id').all().map(row=>row.id);db.close();console.log(JSON.stringify(ids));")
 assert global_ids==[row['id']for row in result],'Global workflow rows differ from complete visible fixture registry'
 return result
def account(user):
 result=node("const fs=require('fs');const{DatabaseSync}=require('node:sqlite');const value=JSON.parse(fs.readFileSync(0,'utf8'));const db=new DatabaseSync('/home/node/.n8n/database.sqlite');const changed=db.prepare('UPDATE user SET email=?,password=? WHERE id=?').run(value.email,value.password,value.id).changes;db.close();console.log(JSON.stringify({changed}));",user);assert result==dict(changed=1);assert login(user['email'])['id']==user['id']
def calibrate(existing=False):
 directory=artifacts/('calibration-'+tag);assert not directory.exists();directory.mkdir();container=command(['ps','-q','target']).decode().strip();assert container
 env=dict(os.environ,N8N_NATIVE_EXISTING='1'if existing else'0');argv=['python3','-B',str(root/'native_controls.py'),container,base,version,str(directory)];r=subprocess.run(argv,env=env,capture_output=True,text=True,timeout=180);journal.append(dict(argv=argv,actual_exit=r.returncode,stdout=r.stdout,stderr=r.stderr));save();assert r.returncode==0,r.stdout+r.stderr
 for row in [json.loads(line)for line in(directory/'native-http.jsonl').read_text().splitlines()]:
  if row['method']=='POST'and row['path']in['/rest/login','/rest/owner/setup']and row['status']==200:
   request=json.loads(base64.b64decode(row['request_base64']));issued=SimpleCookie();issued.load(row['response_headers']['Set-Cookie']);cookies[request.get('emailOrLdapLoginId',request.get('email'))]=issued['n8n-auth'].value
 return json.loads((directory/'native-controls.json').read_text()),json.loads((directory/'native-metadata.json').read_text())
def compact():
 program=r"""const fs=require('fs'),crypto=require('crypto');const{DatabaseSync}=require('node:sqlite');const file='/home/node/.n8n/database.sqlite';const db=new DatabaseSync(file);db.exec('PRAGMA busy_timeout=5000');const count=table=>db.prepare('SELECT count(*) AS count FROM '+table).get().count;if(count('execution_entity')!==0||count('execution_data')!==0)throw Error('Execution rows were not restored before fixture compaction');function logical(){const schema=db.prepare("SELECT type,name,tbl_name,sql FROM sqlite_master WHERE name NOT LIKE 'sqlite_%' ORDER BY type,name").all();const tables=schema.filter(row=>row.type==='table').map(row=>row.name);const rows={};for(const table of tables)rows[table]=db.prepare('SELECT * FROM "'+table.replaceAll('"','""')+'"').all().map(row=>JSON.stringify(row)).sort();return crypto.createHash('sha256').update(JSON.stringify({schema,rows})).digest('hex');}function metrics(){return{pages:db.prepare('PRAGMA page_count').get().page_count,free:db.prepare('PRAGMA freelist_count').get().freelist_count,bytes:fs.statSync(file).size};}const before=metrics(),original=logical();if(before.free>0)db.exec('VACUUM');const after=metrics(),current=logical();db.close();if(original!==current)throw Error('Logical database data changed during fixture compaction');console.log(JSON.stringify({before,after,logical_sha256:current,logical_unchanged:true,execution_rows:0}));"""
 result=node(program)
 assert result['logical_unchanged']is True and result['execution_rows']==0
 return result
def vendor():
 expected=json.loads((root/'vendor.json').read_text())['installed'][version]
 program="""const fs=require('fs'),path=require('path'),crypto=require('crypto');const root=path.dirname(path.dirname(fs.realpathSync('/usr/local/bin/n8n')));const expected=JSON.parse(fs.readFileSync(0,'utf8'));const out={node:process.version,sqlite:process.versions.sqlite,packages:{},sources:{}};for(const name of Object.keys(expected.packages)){const dir=name==='n8n'?root:fs.realpathSync(path.join(root,'node_modules',name));out.packages[name]=JSON.parse(fs.readFileSync(path.join(dir,'package.json'),'utf8')).version;}for(const name of Object.keys(expected.sources)){const [pkg,relative]=name.split('/dist/');const dir=pkg==='n8n'?root:fs.realpathSync(path.join(root,'node_modules',pkg));out.sources[name]=crypto.createHash('sha256').update(fs.readFileSync(path.join(dir,'dist',relative))).digest('hex');}console.log(JSON.stringify(out));"""
 result=node(program,expected);assert result==expected;return result
fixtures=json.loads((root/'jwt-fixtures.json').read_text())
if action=='before':
 assert not state_path.exists();status,body=http('/rest/settings',anonymous=True);assert status==200 and json.loads(body)['data']['versionCli']==version
 installed=vendor();calibration,metadata=calibrate();compact();original=metadata['user'];canonical=dict(id=original['id'],email=fixtures['ordinary']['email'],password=fixtures['ordinary']['password_hash']);account(canonical)
 member=node((root/'member_fixture.js').read_text(),dict(action='create',owner_id=original['id']))
 assert member['password']!='ModuleTarget-native-123!'
 status,body=http('/rest/login','POST',dict(emailOrLdapLoginId=member['email'],email=member['email'],password=member['password']),anonymous=True)
 assert status==200,(status,body)
 reader=json.loads(body)['data'];assert reader['id']==member['id']and reader['role']=='global:member'and'user:create'not in reader['globalScopes']
 reader_credentials=dict(id=member['id'],email=member['email'],password=member['password'],role=reader['role'])
 foreign=[]
 for name in ['Native preserved workflow café','Native preserved workflow '+('long-'*12)]:
  status,body=http('/rest/workflows','POST',dict(name=name,active=False,nodes=[],connections={},settings={}));assert status in [200,201];foreign.append(json.loads(body)['data']['id'])
 values={'binary':b'Module exact bytes\x00\xff\xc3\xa9\n','text':b'Module plain text\n','unicode':'Module café 雪\n'.encode(),'empty':b'','large':b'0123456789abcdef'*4096+b'!','filename':b'Filename path content\n'}
 files={name:dict(path='/tmp/module target café 雪.txt'if name=='filename'else'/tmp/module-target-n8n-'+name,base64=base64.b64encode(value).decode(),sha256=hashlib.sha256(value).hexdigest())for name,value in values.items()}
 node("const fs=require('fs');const data=JSON.parse(fs.readFileSync(0,'utf8'));for(const item of Object.values(data))fs.writeFileSync(item.path,Buffer.from(item.base64,'base64'),{mode:0o600});console.log('true');",files)
 missing_path='/tmp/module-target-n8n-absent';denied_path='/tmp/module-target-n8n-root-denied'
 command(['exec','-T','--user','0','target','node','-e',"const fs=require('fs');const value=JSON.parse(fs.readFileSync(0,'utf8'));fs.writeFileSync(value,'Root-only fixture',{mode:0});fs.chmodSync(value,0);fs.chownSync(value,0,0);console.log('true');"],json.dumps(denied_path).encode())
 permission=node("const fs=require('fs');const value=JSON.parse(fs.readFileSync(0,'utf8'));if(fs.existsSync(value.missing))throw Error('Missing fixture unexpectedly exists');let code=null;try{fs.readFileSync(value.denied);}catch(error){code=error.code;}if(code!=='EACCES')throw Error('Denied fixture is readable');console.log(JSON.stringify({uid:process.getuid(),missing:true,denied_code:code}));",dict(missing=missing_path,denied=denied_path))
 assert permission==dict(uid=1000,missing=True,denied_code='EACCES')
 refused=node("const net=require('net');const socket=net.connect(1,'127.0.0.1');socket.once('connect',()=>{socket.destroy();process.exit(1)});socket.once('error',error=>{if(error.code!=='ECONNREFUSED')process.exit(1);console.log(JSON.stringify({refused:true}));});")
 assert refused==dict(refused=True)
 state=dict(reader=reader_credentials,member=member,missing_path=missing_path,denied_path=denied_path,cookies=cookies,original=original,kind='ordinary',foreign=foreign,baseline=registry(),files=files,vendor=installed,calibration=calibration);state_path.write_text(json.dumps(state,indent=2)+'\n');print(json.dumps(dict(version=version,reader=reader_credentials,missing_path=missing_path,denied_path=denied_path,owner_id=original['id'],files=files,flow_ids=sorted(foreign),encryption_key=metadata['encryptionKey'],vendor=installed,calibration=calibration)));sys.exit(0)
state=json.loads(state_path.read_text());cookies.update(state['cookies']);current=fixtures[state['kind']];login(current['email'])
if action=='token':
 request=json.loads((artifacts/('token-'+tag+'.json')).read_text());status,body=http('/rest/login',anonymous=True,headers={'Cookie':'n8n-auth='+request['token']});result=dict(status=status)
 if status==200:
  user=json.loads(body)['data'];result.update(id=user['id'],email=user['email'],role=user['role'],can_create_users='user:create'in user['globalScopes'])
 print(json.dumps(result));sys.exit(0)
assert registry()==state['baseline'],'Complete fixture workflow records changed'
compact()
if action=='registry':print(json.dumps(dict(flow_ids=sorted(state['foreign']),preserved=True)));sys.exit(0)
if action=='seed':
 assert tag in fixtures;user=fixtures[tag];account(dict(id=state['original']['id'],email=user['email'],password=user['password_hash']));state.update(kind=tag,baseline=registry());state_path.write_text(json.dumps(state,indent=2)+'\n');print(json.dumps(dict(email=user['email'],password='ModuleTarget-native-123!',password_hash=user['password_hash'],claim=user['expected_claim'],id=state['original']['id'])));sys.exit(0)
assert action=='after'
for flow_id in reversed(state['foreign']):
 status,body=http('/rest/workflows/'+flow_id+'/archive','POST');assert status==200
 status,body=http('/rest/workflows/'+flow_id,'DELETE');assert status==200 and json.loads(body)['data']is True
assert registry()==[]
node((root/'member_fixture.js').read_text(),dict(action='remove'))
command(['exec','-T','--user','0','target','node','-e',"const fs=require('fs');fs.unlinkSync(JSON.parse(fs.readFileSync(0,'utf8')));console.log('true');"],json.dumps(state['denied_path']).encode())
node("const fs=require('fs'),crypto=require('crypto');const files=JSON.parse(fs.readFileSync(0,'utf8'));for(const value of Object.values(files)){if(crypto.createHash('sha256').update(fs.readFileSync(value.path)).digest('hex')!==value.sha256)throw Error('Native file changed');fs.unlinkSync(value.path);}console.log('true');",state['files'])
account(state['original']);calibration,_=calibrate(existing=True);assert calibration==state['calibration'];compact();assert vendor()==state['vendor'];assert registry()==[]
print(json.dumps(dict(restored=True,flow_ids=[],vendor=state['vendor'],calibration=calibration)))
