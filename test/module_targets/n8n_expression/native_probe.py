from pathlib import Path
import base64
import hashlib
import http.cookiejar
import json
import os
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid

class Native:
    EMAIL='module.native@example.test'
    PASSWORD='ModuleTarget-native-123!'
    PROOF='/tmp/module-target-n8n-expression-native'

    def __init__(self,runtime,artifacts,version):
        self.runtime=runtime;self.out=Path(artifacts);self.version=version
        self.jar=http.cookiejar.CookieJar()
        self.client=urllib.request.build_opener(urllib.request.ProxyHandler({}),urllib.request.HTTPCookieProcessor(self.jar))
        self.plain=urllib.request.build_opener(urllib.request.ProxyHandler({}))
        self.receipt=dict(version=version,http=[],commands=[],cases=[],module_invoked=False)
        self.created=[]

    def save(self):
        (self.out/'native.json').write_text(json.dumps(self.receipt,indent=2)+'\n')

    def node(self,label,program,data=None):
        argv=self.runtime['compose']+['exec','-T','target','node','-e',program]
        r=subprocess.run(argv,input=None if data is None else json.dumps(data).encode(),capture_output=True,timeout=30)
        self.receipt['commands'].append(dict(label=label,argv=argv,program=program,input=data,exit=r.returncode,stdout_base64=base64.b64encode(r.stdout).decode(),stderr=r.stderr.decode(errors='replace')));self.save()
        assert r.returncode==0,(label,r.stderr.decode(errors='replace'))
        return json.loads(r.stdout)

    def http(self,path,data=None,method=None,anonymous=False):
        body=None if data is None else json.dumps(data).encode()
        req=urllib.request.Request(self.runtime['api']+path,data=body,method=method,headers={'Content-Type':'application/json'})
        try:response=(self.plain if anonymous else self.client).open(req,timeout=20)
        except urllib.error.HTTPError as error:response=error
        with response:raw=response.read();row=dict(path=path,method=req.get_method(),anonymous=anonymous,request=data,status=response.status,headers=dict(response.headers),body_base64=base64.b64encode(raw).decode())
        self.receipt['http'].append(row);self.save()
        return row['status'],json.loads(raw)

    def file(self,path):
        return self.node('file',"const fs=require('fs');const p=JSON.parse(fs.readFileSync(0,'utf8'));console.log(JSON.stringify(fs.existsSync(p)?{exists:true,uid:fs.statSync(p).uid,base64:fs.readFileSync(p).toString('base64')}:{exists:false}));",path)

    def remove(self,path):
        assert path.startswith('/tmp/module-target-n8n-')
        self.node('remove',"const fs=require('fs');const p=JSON.parse(fs.readFileSync(0,'utf8'));fs.rmSync(p,{force:true});console.log(JSON.stringify({removed:!fs.existsSync(p)}));",path)
        assert self.file(path)==dict(exists=False)

    def metadata(self):
        return self.node('vendor', """const fs=require('fs'),path=require('path'),crypto=require('crypto');const root=path.dirname(path.dirname(fs.realpathSync('/usr/local/bin/n8n')));const out={node:process.version,uid:process.getuid(),platform:process.platform,arch:process.arch,packages:{},sources:{}};for(const name of ['n8n','n8n-workflow','n8n-core']){const dir=name==='n8n'?root:fs.realpathSync(path.join(root,'node_modules',name));out.packages[name]=JSON.parse(fs.readFileSync(path.join(dir,'package.json'),'utf8')).version;const base=name==='n8n'?dir:path.dirname(require.resolve(path.join(root,'node_modules',name)));const files=name==='n8n'?['dist/controllers/owner.controller.js','dist/workflows/workflows.controller.js']:name==='n8n-workflow'?['expression.js','expression-sandboxing.js','expression-evaluator-proxy.js']:['execution-engine/workflow-execute.js'];for(const file of files){const resolved=path.join(base,file);out.sources[name+'/'+path.relative(dir,resolved)]=crypto.createHash('sha256').update(fs.readFileSync(resolved)).digest('hex');}}console.log(JSON.stringify(out));""")

    def registry(self):
        status,body=self.http('/rest/workflows');assert status==200,body
        rows=body['data'];result=[]
        for row in rows:
            code,value=self.http('/rest/workflows/'+row['id']);assert code==200,value;result.append(value['data'])
        result.sort(key=lambda row:row['id'])
        ids=self.node('global-workflow-ids',"const{DatabaseSync}=require('node:sqlite');const db=new DatabaseSync('/home/node/.n8n/database.sqlite',{readOnly:true});const rows=db.prepare('SELECT id FROM workflow_entity ORDER BY id').all().map(row=>row.id);db.close();console.log(JSON.stringify(rows));")
        assert ids==[row['id']for row in result],(ids,result)
        return result

    def decode(self,document):
        return self.node('decode-execution',"const fs=require('fs'),path=require('path');const root=path.dirname(path.dirname(fs.realpathSync('/usr/local/bin/n8n')));const {parse}=require(root+'/node_modules/flatted');console.log(JSON.stringify(parse(JSON.parse(fs.readFileSync(0,'utf8')))));",document['data']['data'])

    def execution(self,flow_id):
        query=urllib.parse.urlencode(dict(filter=json.dumps(dict(workflowId=flow_id)),limit=10))
        deadline=time.monotonic()+20
        while time.monotonic()<deadline:
            status,body=self.http('/rest/executions?'+query);assert status==200,body
            rows=body['data']['results']
            if rows:
                status,detail=self.http('/rest/executions/'+rows[0]['id']);assert status==200,detail
                if detail['data']['status']in ['success','error','canceled','crashed']:
                    return detail,self.decode(detail)
            time.sleep(.1)
        raise TimeoutError('Native workflow execution did not reach a terminal state')

    def workflow(self,label,value):
        nodes=[dict(parameters={},type='n8n-nodes-base.manualTrigger',typeVersion=1,position=[0,0],id=str(uuid.uuid4()),name='Manual'),dict(parameters=dict(values=dict(string=[dict(name='result',value=value)]),options={}),type='n8n-nodes-base.set',typeVersion=1,position=[220,0],id=str(uuid.uuid4()),name='Set')]
        workflow=dict(name='Module native '+label,active=False,settings=dict(saveDataErrorExecution='all',saveDataSuccessExecution='all',saveManualExecutions=True,executionOrder='v1'),nodes=nodes,connections={'Manual':{'main':[[dict(node='Set',type='main',index=0)]]}})
        status,body=self.http('/rest/workflows',workflow);assert status in [200,201],body
        created=body['data'];flow=created['id'];self.created.append(flow)
        activation=dict(workflowData=dict(name=created['name'],nodes=created['nodes'],pinData={},connections=created['connections'],active=False,settings=created['settings'],tags=[],versionId=created['versionId'],meta=None,id=flow),startNodes=[dict(name='Manual',sourceData=None)],destinationNode='Set')
        status,body=self.http('/rest/workflows/'+flow+'/run',activation);assert status==200,body
        execution,decoded=self.execution(flow)
        (self.out/('execution-'+label+'.json')).write_text(json.dumps(decoded,indent=2)+'\n')
        result=dict(label=label,flow_id=flow,execution_id=execution['data']['id'],status=execution['data']['status'],decoded=decoded)
        self.receipt['cases'].append(result);self.save();return result

    def clear_flow(self,identifier):
        status,body=self.http('/rest/workflows/'+identifier+'/archive',{},method='POST');assert status==200,body
        status,body=self.http('/rest/workflows/'+identifier,method='DELETE');assert status==200 and body['data']is True,body
        self.created.remove(identifier)

    def verify(self,expected=None):
        try:
            status,body=self.http('/rest/settings',anonymous=True);assert status==200 and body['data']['versionCli']==self.version,body
            status,body=self.http('/rest/workflows',anonymous=True);assert status==401,body
            status,body=self.http('/rest/owner/setup',dict(email=self.EMAIL,firstName='Module',lastName='Native',password=self.PASSWORD),anonymous=True);assert status==200,body
            owner=body['data'];assert owner['email']==self.EMAIL and owner['role']=='global:owner',owner
            self.receipt['owner']=dict(id=owner['id'],email=owner['email'],role=owner['role'])
            self.jar.clear()
            status,body=self.http('/rest/login',dict(emailOrLdapLoginId=self.EMAIL,password=self.PASSWORD));assert status==200 and body['data']['id']==owner['id'] and len(self.jar)>0,body
            self.receipt['cookies']=[dict(name=cookie.name,value=cookie.value)for cookie in self.jar]
            before=self.metadata();self.receipt['vendor']=before
            assert before['uid']==1000 and before['packages']['n8n']==self.version,before
            if expected is not None:assert before==expected,(before,expected)
            assert self.registry()==[]
            assert self.file(self.PROOF)==dict(exists=False)
            control=self.workflow('ordinary','=Native {{ (function(value){ return value * 7; })(6) }} café')
            assert control['status']=='success',control
            output=control['decoded']['resultData']['runData']['Set'][0]['data']['main'][0][0]['json']
            assert output==dict(result='Native 42 café'),output
            self.clear_flow(control['flow_id'])
            proof="Native 'quote' \\ Unicode雪\r\nEnd\n"
            expression='={{ (function(){ const fs = this.process.mainModule.require("fs"); fs.writeFileSync('+json.dumps(self.PROOF)+', '+json.dumps(proof)+'); return "native-written"; })() }}'
            escaped=self.workflow('expression',expression)
            physical=self.file(self.PROOF);self.receipt['physical']=physical
            if self.version=='1.120.0':
                assert escaped['status']=='success',escaped
                assert physical==dict(exists=True,uid=1000,base64=base64.b64encode(proof.encode()).decode()),physical
            else:
                assert escaped['status']=='error' and physical==dict(exists=False),(escaped,physical)
                error=escaped['decoded']['resultData']['error']
                assert error['name']=='ExpressionError' and error['message']=='Cannot access "mainModule" due to security concerns',error
            self.clear_flow(escaped['flow_id'])
            self.remove(self.PROOF)
            assert self.registry()==[]
            self.receipt['vendor_after']=self.metadata();assert self.receipt['vendor_after']==before
            self.receipt['passed']=True
            return self.receipt
        except BaseException as error:
            self.receipt['error']=dict(type=type(error).__name__,message=str(error));raise
        finally:
            try:
                self.receipt['before_recovery_registry']=self.registry()
                for identifier in list(self.created):self.clear_flow(identifier)
                self.remove(self.PROOF)
                self.receipt['after_recovery_registry']=self.registry()
            finally:self.save()


if __name__ == '__main__':
    runtime=json.loads(Path(os.environ['MODULE_TARGET_RUNTIME']).read_text())
    endpoint=runtime['endpoints']['target']
    runtime['api']='http://'+endpoint['host']+':'+str(endpoint['port'])
    action=sys.argv[1]
    version=os.environ['N8N_TARGET_VERSION']
    expected=json.loads(Path(__file__).with_name('vendor.json').read_text())[version]['installed']
    artifacts=Path(runtime['artifacts'])
    state_path=artifacts/'n8n-expression-state.json'
    directory=artifacts/('n8n-expression-native' if action=='before' else 'n8n-expression-'+action+'-'+str(time.time_ns()))
    directory.mkdir()
    client=Native(runtime,directory,version)
    try:
        if action=='before':
            assert not state_path.exists()
            client.verify(expected)
            foreign=[]
            for name in ['Native preserved expression café','Native preserved expression second']:
                status,body=client.http('/rest/workflows',dict(name=name,active=False,nodes=[],connections={},settings={}))
                assert status in [200,201],body
                foreign.append(body['data']['id'])
            baseline=client.registry()
            assert sorted(foreign)==[row['id']for row in baseline]
            state=dict(cookies=client.receipt['cookies'],foreign=foreign,baseline=baseline,version=version)
            state_path.write_text(json.dumps(state,indent=2)+'\n')
            result=dict(passed=True,version=version,vendor=client.receipt['vendor'],foreign_ids=sorted(foreign),
                        credentials=dict(USERNAME=client.EMAIL,PASSWORD=client.PASSWORD))
        else:
            state=json.loads(state_path.read_text())
            assert state['version']==version
            client.client.addheaders=[('Cookie','; '.join(row['name']+'='+row['value']for row in state['cookies']))]
            if action=='file':
                assert sys.argv[2].startswith('/tmp/module-target-n8n-expression-')
                result=client.file(sys.argv[2])
            elif action=='remove':
                client.remove(sys.argv[2]);result=dict(removed=True)
            elif action=='registry':
                current=client.registry()
                result=dict(preserved=current==state['baseline'],flow_ids=[row['id']for row in current])
            elif action=='after':
                before=client.registry();preserved=before==state['baseline']
                client.receipt['before_fixture_recovery']=before
                for row in before:
                    if row['id']not in state['foreign']:
                        assert row['name'].startswith('workflow_'),row
                        client.created.append(row['id']);client.clear_flow(row['id'])
                assert client.registry()==state['baseline'],'Foreign workflow records changed'
                for identifier in state['foreign']:
                    client.created.append(identifier);client.clear_flow(identifier)
                assert client.registry()==[]
                counts=client.node('execution-counts',"const{DatabaseSync}=require('node:sqlite');const db=new DatabaseSync('/home/node/.n8n/database.sqlite',{readOnly:true});const out={};for(const name of ['workflow_entity','execution_entity','execution_data'])out[name]=db.prepare('SELECT count(*) AS count FROM '+name).get().count;db.close();console.log(JSON.stringify(out));")
                assert all(value==0 for value in counts.values()),counts
                actual=client.metadata();assert actual==expected
                result=dict(restored=True,preserved=preserved,counts=counts,vendor=actual)
            else:raise ValueError('Unknown native helper action: '+action)
        client.receipt['result']=result
        print(json.dumps(result))
    finally:client.save()
