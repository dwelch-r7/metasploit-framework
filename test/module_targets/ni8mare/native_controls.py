from pathlib import Path
import sqlite3
import base64,hashlib,hmac,http.cookiejar,json,os,subprocess,sys,time,urllib.request,urllib.error,urllib.parse,uuid
container,endpoint,version,folder=sys.argv[1:];directory=Path(folder);env=dict(os.environ,DOCKER_CONTEXT='default',BUILDX_BUILDER='default');jar=http.cookiejar.CookieJar();opener=urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar));plain=urllib.request.build_opener();proofs=[]
def http(path,method='GET',data=None,*,anonymous=False,headers=None,_rate_retry=False):
 headers=dict(headers or {});body=data
 if isinstance(data,(dict,list)):body=json.dumps(data).encode();headers['Content-Type']='application/json'
 request=urllib.request.Request(endpoint+path,data=body,headers=headers,method=method)
 try:
  response=(plain if anonymous else opener).open(request,timeout=30);status=response.status;payload=response.read();response_headers=dict(response.headers)
 except urllib.error.HTTPError as error:status=error.code;payload=error.read();response_headers=dict(error.headers)
 with (directory/'native-http.jsonl').open('a')as log:log.write(json.dumps(dict(at=time.time(),path=path,method=method,anonymous=anonymous,request_headers=headers,request_base64=base64.b64encode(body).decode()if body is not None else None,status=status,response_headers=response_headers,response_base64=base64.b64encode(payload).decode()))+'\n')
 if path=='/rest/login'and method=='POST'and status==429 and not _rate_retry:
  delay=int(response_headers['Retry-After']);assert 0<delay<=60
  with (directory/'native-auth-waits.jsonl').open('a')as log:log.write(json.dumps(dict(at=time.time(),seconds=delay,reason='Genuine default authentication rate limit'))+'\n')
  time.sleep(delay+0.1)
  return http(path,method,data,anonymous=anonymous,headers=headers,_rate_retry=True)
 return status,payload

def node(program,data=None):
 r=subprocess.run(['docker','exec','-i',container,'node','-e',program],input=json.dumps(data).encode()if data is not None else None,env=env,capture_output=True,timeout=45)
 with (directory/'native-node.jsonl').open('a')as log:log.write(json.dumps(dict(program=program,input=data,actual_exit=r.returncode,stdout_base64=base64.b64encode(r.stdout).decode(),stderr_base64=base64.b64encode(r.stderr).decode()))+'\n')
 assert r.returncode==0,r.stderr.decode();return json.loads(r.stdout)

def workflows():
 status,body=http('/rest/workflows');assert status==200,(status,body);doc=json.loads(body);assert isinstance(doc['data'],list);return sorted(doc['data'],key=lambda v:v['id'])

def decode_execution(document):
 flattened=document['data']['data'];assert isinstance(flattened,str)
 return node("const fs=require('fs'),path=require('path');const root=path.dirname(path.dirname(fs.realpathSync('/usr/local/bin/n8n')));const{parse}=require(root+'/node_modules/flatted');console.log(JSON.stringify(parse(JSON.parse(fs.readFileSync(0,'utf8')))));",flattened)

def binaries(value):
 result=[]
 if isinstance(value,dict):
  if set(['data','fileName','mimeType'])<=set(value):result.append(value)
  else:
   for item in value.values():result.extend(binaries(item))
 elif isinstance(value,list):
  for item in value:result.extend(binaries(item))
 return result

status,body=http('/rest/workflows',anonymous=True);assert status==401,(status,body)
if os.environ.get('N8N_NATIVE_EXISTING')=='1':
 status,body=http('/rest/login','POST',dict(emailOrLdapLoginId='module.native@example.test',email='module.native@example.test',password='ModuleTarget-native-123!'))
else:
 status,body=http('/rest/owner/setup','POST',dict(email='module.native@example.test',firstName='Module',lastName='Native',password='ModuleTarget-native-123!'))
assert status==200,(status,body);owner=json.loads(body)['data'];assert owner['email']=='module.native@example.test';assert len(jar)>0
baseline=workflows();assert baseline==[]
fixture=b'Module target n8n exact native bytes\n\x00\xff\xc3\xa9'
path='/tmp/module-target-n8n-native-canary'
assert node("const fs=require('fs');const d=JSON.parse(fs.readFileSync(0,'utf8'));fs.writeFileSync(d.path,Buffer.from(d.base64,'base64'),{mode:0o600});console.log(JSON.stringify({uid:process.getuid(),bytes:fs.statSync(d.path).size}));",dict(path=path,base64=base64.b64encode(fixture).decode()))==dict(uid=1000,bytes=len(fixture))

def run_file(case,confused,source_path=None,db_user=None,config_key=None):
 flow_id=None;webhook=str(uuid.uuid4());name='On form submission'
 workflow=dict(name='Module native '+case,active=False,settings=dict(saveDataErrorExecution='all',saveDataSuccessExecution='all',saveManualExecutions=True,executionOrder='v1'),nodes=[dict(parameters=dict(formTitle='Module native',formFields=dict(values=[dict(fieldLabel='Native file',fieldType='file')]),options={}),type='n8n-nodes-base.formTrigger',typeVersion=2.3,position=[0,0],id=str(uuid.uuid4()),name=name,webhookId=webhook)],connections={})
 try:
  status,body=http('/rest/workflows','POST',workflow);assert status in [200,201],(status,body);created=json.loads(body)['data'];flow_id=created['id']
  activation=dict(workflowData=dict(name=workflow['name'],nodes=created['nodes'],pinData={},connections={},active=False,settings=workflow['settings'],tags=[],versionId=created['versionId'],meta=None,id=flow_id),startNodes=[dict(name=name,sourceData=None)],destinationNode=name)
  status,body=http('/rest/workflows/'+flow_id+'/run','POST',activation);assert status==200,(status,body);started=json.loads(body)['data'];assert started.get('waitingForWebhook')is True,started
  if confused:
   status,body=http('/form-test/'+webhook,'POST',dict(files={'field-0':dict(filepath=source_path or path,originalFilename='native.bin',mimeType='application/octet-stream',extenstion='')},data=['native'],executionId='native'),anonymous=True)
  else:
   boundary='ModuleTargetNativeBoundary';payload=('--'+boundary+'\r\nContent-Disposition: form-data; name="field-0"; filename="native.bin"\r\nContent-Type: application/octet-stream\r\n\r\n').encode()+fixture+('\r\n--'+boundary+'--\r\n').encode();status,body=http('/form-test/'+webhook,'POST',payload,anonymous=True,headers={'Content-Type':'multipart/form-data; boundary='+boundary})
  submitted=dict(status=status,body_base64=base64.b64encode(body).decode());deadline=time.monotonic()+20;execution=None
  while time.monotonic()<deadline:
   query=urllib.parse.urlencode(dict(filter=json.dumps(dict(workflowId=flow_id)),limit=10));code,reply=http('/rest/executions?'+query);assert code==200,(code,reply);rows=json.loads(reply)['data']['results']
   if rows:
    code,reply=http('/rest/executions/'+rows[0]['id']);assert code==200;document=json.loads(reply);execution=document
    if document['data'].get('status')in['success','error','canceled','crashed']:break
   time.sleep(.1)
  expected=not confused or version=='1.120.0'
  if expected:
   assert execution and execution['data']['status']=='success',(submitted,execution)
   decoded=decode_execution(execution);(directory/('execution-'+case+'.json')).write_text(json.dumps(decoded,indent=2)+'\n');found=binaries(decoded);assert len(found)==1,found;actual=base64.b64decode(found[0]['data'],validate=True)
   if db_user:
    snapshot=directory/(case+'.sqlite');snapshot.write_bytes(actual)
    with sqlite3.connect('file:'+str(snapshot.resolve())+'?mode=ro',uri=True)as database:
     database.row_factory=sqlite3.Row;row=database.execute('SELECT id,email,password FROM user WHERE id=?',(db_user['id'],)).fetchone();assert row and dict(row)==db_user,(row,db_user)
   elif config_key:assert json.loads(actual)['encryptionKey']==config_key
   else:assert actual==fixture,found
  else:
   if execution and execution['data'].get('data'):
    decoded=decode_execution(execution);(directory/('execution-'+case+'.json')).write_text(json.dumps(decoded,indent=2)+'\n');assert binaries(decoded)==[],decoded;assert decoded.get('resultData',{}).get('error',{}).get('message')=='Expected multipart/form-data',decoded
   assert not execution or execution['data']['status']!='success',(submitted,execution)
  proofs.append(dict(case=case,confused=confused,expected_file_read=expected,submission=submitted,execution_status=execution['data'].get('status')if execution else None))
 finally:
  if flow_id:
   status,body=http('/rest/workflows/'+flow_id+'/archive','POST');assert status==200,(status,body)
   status,body=http('/rest/workflows/'+flow_id,'DELETE');assert status==200 and json.loads(body)['data']is True,(status,body)
   assert workflows()==baseline

for attempt in range(2):run_file('multipart-'+str(attempt),False)
for attempt in range(2):run_file('json-confusion-'+str(attempt),True)
# Read-only native metadata uses Node's installed SQLite implementation, not a file-read oracle supplied to the owner.
metadata=node("const fs=require('fs');const{DatabaseSync}=require('node:sqlite');const db=new DatabaseSync('/home/node/.n8n/database.sqlite',{readOnly:true});const user=db.prepare('SELECT id,email,password FROM user WHERE id=?').get(JSON.parse(fs.readFileSync(0,'utf8')));db.close();const config=JSON.parse(fs.readFileSync('/home/node/.n8n/config','utf8'));console.log(JSON.stringify({user,encryptionKey:config.encryptionKey}));",owner['id'])
(directory/'native-metadata.json').write_text(json.dumps(metadata,indent=2)+'\n')
secret=hashlib.sha256(metadata['encryptionKey'][::2].encode()).hexdigest().encode()
def ticket(user,urlsafe=False):
 digest=hashlib.sha256((user['email']+':'+user['password']).encode()).digest();claim=(base64.urlsafe_b64encode(digest)if urlsafe else base64.b64encode(digest)).decode()[:10]
 encode=lambda data:base64.urlsafe_b64encode(data).decode().rstrip('=');head=encode(b'{"alg":"HS256","typ":"JWT"}');body=encode(json.dumps(dict(id=user['id'],hash=claim),separators=(',',':')).encode());unsigned=head+'.'+body;return unsigned+'.'+encode(hmac.digest(secret,unsigned.encode(),'sha256')),claim
for style in [False,True]:
 token,claim=ticket(metadata['user'],style);status,body=http('/rest/login',anonymous=True,headers={'Cookie':'n8n-auth='+token});assert status==(401 if style and any(c in ticket(metadata['user'])[1]for c in '+/')else 200),(status,body);proofs.append(dict(case='native-jwt',urlsafe=style,claim=claim,status=status))
fixtures=json.loads((Path(__file__).parent/'jwt-fixtures.json').read_text())
try:
 for kind,fixture_user in fixtures.items():
  update=dict(id=owner['id'],email=fixture_user['email'],password=fixture_user['password_hash'],plain='ModuleTarget-native-123!')
  assert node("const fs=require('fs'),path=require('path');const root=path.dirname(path.dirname(fs.realpathSync('/usr/local/bin/n8n')));const bcrypt=require(root+'/node_modules/bcryptjs');const data=JSON.parse(fs.readFileSync(0,'utf8'));if(!bcrypt.compareSync(data.plain,data.password))throw Error('Fixture hash does not match password');const{DatabaseSync}=require('node:sqlite');const db=new DatabaseSync('/home/node/.n8n/database.sqlite');const result=db.prepare('UPDATE user SET email=?,password=? WHERE id=?').run(data.email,data.password,data.id);db.close();console.log(JSON.stringify({changed:result.changes}));",update)==dict(changed=1)
  jar.clear();status,body=http('/rest/login','POST',dict(emailOrLdapLoginId=update['email'],email=update['email'],password=update['plain']));assert status==200,(status,body)
  user=dict(id=owner['id'],email=update['email'],password=update['password']);assert ticket(user)[1]==fixture_user['expected_claim']
  for style in [False,True]:
   token,claim=ticket(user,style);status,body=http('/rest/login',anonymous=True,headers={'Cookie':'n8n-auth='+token});assert status==(401 if style and kind!='ordinary'else 200),(kind,style,status,body);proofs.append(dict(case='native-jwt-'+kind,urlsafe=style,claim=claim,status=status))
  run_file('database-'+kind,True,source_path='/home/node/.n8n/database.sqlite',db_user=user)
  token,_=ticket(user);signature=token.rsplit('.',1)[1];wrong=token.rsplit('.',1)[0]+'.'+('A'if signature[0]!='A'else'B')+signature[1:];status,body=http('/rest/login',anonymous=True,headers={'Cookie':'n8n-auth='+wrong});assert status==401;proofs.append(dict(case='native-jwt-invalid-'+kind,status=status))
finally:
 original=metadata['user'];node("const fs=require('fs');const{DatabaseSync}=require('node:sqlite');const value=JSON.parse(fs.readFileSync(0,'utf8'));const db=new DatabaseSync('/home/node/.n8n/database.sqlite');const result=db.prepare('UPDATE user SET email=?,password=? WHERE id=?').run(value.email,value.password,value.id);db.close();console.log(JSON.stringify({changed:result.changes}));",original)
 jar.clear();status,body=http('/rest/login','POST',dict(emailOrLdapLoginId=original['email'],email=original['email'],password='ModuleTarget-native-123!'));assert status==200
for attempt in range(2):run_file('config-'+str(attempt),True,source_path='/home/node/.n8n/config',config_key=metadata['encryptionKey'])
assert workflows()==baseline
node("const fs=require('fs');const p=JSON.parse(fs.readFileSync(0,'utf8'));fs.unlinkSync(p);console.log('true');",path)
(directory/'native-controls.json').write_text(json.dumps(dict(version=version,proofs=proofs,registry_restored=True,owner_id=owner['id']),indent=2)+'\n');print(json.dumps(dict(version=version,controls=len(proofs),registry_restored=True)))
