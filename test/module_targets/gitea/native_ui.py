"""Independent genuine cookie/form controls for the modules' web-interface paths."""
import base64
import http.cookiejar
from html.parser import HTMLParser
import json
import urllib.error
import urllib.parse
import urllib.request
from native_client import NativeGitea, PROFILES


class Fields(HTMLParser):
    def __init__(self, text):
        super().__init__();self.inputs=[];self.links=[];self.current_link=None;self.tasks=[];self.feed(text)

    def handle_starttag(self, tag, attributes):
        attrs=dict(attributes)
        if tag=='input':self.inputs.append(attrs)
        if attrs.get('id')=='repo_migrating':self.tasks.append(attrs['task'])
        if tag=='a':self.current_link=attrs.get('href')
        if tag=='svg' and attrs.get('class')=='svg gitea-gitea':self.links.append(self.current_link)

    def value(self, name):
        return next(row['value']for row in self.inputs if row.get('name')==name or row.get('id')==name)


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, response, code, message, headers, url):return None


class NativeUI:
    def __init__(self, native, service):
        self.native=native;self.service=service
        endpoint=native.runtime['endpoints'][service]
        self.origin='http://'+endpoint['host']+':'+str(endpoint['port'])
        self.prefix=PROFILES[service][3].rstrip('/')
        self.jar=http.cookiejar.CookieJar()
        self.opener=urllib.request.build_opener(urllib.request.HTTPCookieProcessor(self.jar),NoRedirect())

    def request(self, path, data=None):
        url=self.origin+self.prefix+path
        request=urllib.request.Request(url,data=urllib.parse.urlencode(data).encode()if data is not None else None)
        try:response=self.opener.open(request,timeout=10)
        except urllib.error.HTTPError as error:response=error
        body=response.read();text=body.decode('utf-8','backslashreplace')
        row={'service':self.service,'kind':'native-ui','url':url,'method':request.get_method(),'request':data,'status':response.status,'headers':dict(response.headers),'body_base64':base64.b64encode(body).decode(),'cookies':[{'name':cookie.name,'domain':cookie.domain,'path':cookie.path}for cookie in self.jar]}
        self.native.records['http'].append(row)
        with (self.native.artifacts/'native-gitea-http.jsonl').open('a')as output:output.write(json.dumps(row)+'\n')
        return response.status,text,Fields(text)

    def login(self, credentials):
        status,text,fields=self.request('/user/login');assert status==200,status
        status,text,_=self.request('/user/login',{'_csrf':fields.value('_csrf'),'user_name':credentials[0],'password':credentials[1]});assert status==302,(status,text)
        # The REST API requires its own authentication on these releases.
        # Prove the cookie against the web form, then independently fetch the ID.
        status,text,fields=self.request('/repo/create');assert status==200,(status,text)
        status,identity=self.native.request(self.service,'/api/v1/user',credentials)
        assert status==200 and identity['login']==credentials[0],(status,identity)
        assert fields.value('uid')==str(identity['id']),(identity,fields.inputs)
        return identity

    def hook(self, credentials, permitted):
        identity=self.login(credentials);actor=PROFILES[self.service][2];owner=credentials[0]
        name='module-target-native-web';repo='/'+owner+'/'+name;proof='/tmp/module-target-native-web-proof';before=self.native.tree(self.service)
        self.native.command(actor,'test','!','-e',proof)
        try:
            status,text,fields=self.request('/repo/create');assert status==200,(status,text)
            uid=fields.value('uid');assert str(identity['id'])==uid,(identity,fields.inputs)
            status,text,_=self.request('/repo/create',{'_csrf':fields.value('_csrf'),'uid':uid,'repo_name':name,'auto_init':'on','readme':'Default','default_branch':'master','private':'on'});assert status==302,(status,text)
            status,metadata=self.native.request(self.service,'/api/v1/repos/'+owner+'/'+name,credentials);assert status==200 and metadata['default_branch']=='master',(status,metadata)
            status,text,fields=self.request(repo+'/settings/hooks/git/post-receive')
            if not permitted:
                assert status==404,(status,text)
                self.native.command(actor,'test','!','-e',proof)
            else:
                assert status==200,(status,text)
                script='#!/bin/sh\nid > '+proof+'\n'
                status,text,_=self.request(repo+'/settings/hooks/git/post-receive',{'_csrf':fields.value('_csrf'),'content':script});assert status==302,(status,text)
                status,metadata=self.native.request(self.service,'/api/v1/repos'+repo+'/hooks/git/post-receive',credentials);assert status==200 and metadata['content']==script,(status,metadata)
                status,text,fields=self.request(repo+'/_new/master');assert status==200,(status,text)
                content='Native-UI-'+self.service+'\n'
                status,text,_=self.request(repo+'/_new/master',{'_csrf':fields.value('_csrf'),'last_commit':fields.value('last_commit'),'tree_path':'ui-native.txt','content':content,'commit_summary':'Native UI proof','commit_message':'','commit_choice':'direct'});assert status==302,(status,text)
                actual=self.native.command(actor,'cat',proof);assert 'uid=1000(git)'in actual,actual
                committed=self.native.command(actor,'git','--git-dir','/data/git/repositories'+repo+'.git','show','master:ui-native.txt',user='git');assert committed==content,(committed,content)
                self.native.records.setdefault('ui_proofs',[]).append({'service':self.service,'identity':identity,'uid':uid,'execution':actual,'committed':committed})
            status,text,fields=self.request(repo+'/settings');assert status==200,(status,text)
            status,text,_=self.request(repo+'/settings',{'_csrf':fields.value('_csrf'),'action':'delete','repo_name':name});assert status==302,(status,text)
            assert self.native.request(self.service,'/api/v1/repos'+repo,credentials)[0]==404
        finally:
            self.native.remove_repo(self.service,owner,name,credentials)
            self.native.command(actor,'rm','-f',proof)
        assert self.native.tree(self.service)==before

    def migration(self, permitted=True):
        identity=self.login(self.native.user);owner=self.native.user[0]
        seed='module-target-native-web-seed';name='module-target-native-web-migrate'
        actor=PROFILES[self.service][2];before=self.native.tree(self.service)
        try:
            status,metadata=self.native.request(self.service,'/api/v1/user/repos',self.native.user,{'name':seed,'auto_init':True,'private':False});assert status==201,(status,metadata)
            base='http://prefix/gitea/' if self.service=='prefix' else 'http://'+self.service+':3000/'
            metadata['clone_url']=base+owner+'/'+seed+'.git'
            assert self.native.request('migration','/configure',data={'repository':owner+'/'+name,'metadata':metadata,'command':None})[0]==200
            status,text,fields=self.request('/repo/migrate');assert status==200 and len(fields.links)==1,(status,fields.links)
            actual=fields.links[0];path=actual.removeprefix(self.prefix) if self.prefix else actual
            status,text,fields=self.request(path);assert status==200,(status,text)
            service_type=urllib.parse.parse_qs(urllib.parse.urlparse(actual).query)['service_type'][0]
            data={'_csrf':fields.value('_csrf'),'uid':str(identity['id']),'service':service_type,'pull_requests':'on','repo_name':name,'auth_token':'native-public-token','clone_addr':'http://migration:8000/'+owner+'/'+name}
            status,text,_=self.request(path,data)
            if permitted:
                assert status==302,(status,text)
                # Use the genuine client's bounded retry while the web UI's
                # asynchronous task creates its first master branch.
                branch=json.loads(self.native.command(actor,'curl','--fail','--silent','--show-error','--retry','20','--retry-delay','1','--retry-max-time','20','--retry-all-errors','--max-time','3','--user',':'.join(self.native.user),'http://127.0.0.1:3000/api/v1/repos/'+owner+'/'+name+'/branches/master',timeout=25))
                assert branch['name']=='master',branch
                observations=self.native.request('migration','/observations')[1]
                assert observations['requests'],observations
                expected=self.native.command(actor,'git','--git-dir','/data/git/repositories/'+owner+'/'+seed+'.git','rev-parse','master',user='git').strip()
                actual_commit=self.native.command(actor,'git','--git-dir','/data/git/repositories/'+owner+'/'+name+'.git','rev-parse','master',user='git').strip()
                assert actual_commit==expected,(actual_commit,expected)
                status_page,html,parsed=self.request('/'+owner+'/'+name);assert status_page==200,(status_page,html)
                completion={'status':4,'source':'completed repository page'}
                if parsed.tasks:
                    task_status,task_text,_=self.request('/user/task/'+parsed.tasks[0]);task=json.loads(task_text)
                    assert task_status==200 and task['status']==4,(task_status,task)
                    completion=task
                observations=self.native.request('migration','/observations')[1]
                assert any('/pulls?'in request['path']for request in observations['requests']),observations
            else:
                observations=self.native.request('migration','/observations')[1]
                assert status==200 and 'You can not import from disallowed hosts, please ask the admin to check ALLOWED_DOMAINS/ALLOW_LOCALNETWORKS/BLOCKED_DOMAINS settings.' in text and observations['requests']==[],(status,text,observations)
            self.native.records.setdefault('ui_migrations',[]).append({'service':self.service,'permitted':permitted,'selected_href':actual,'form_route':path,'post_status':status,'observations':observations,'completion':completion if permitted else None})
        finally:
            for repository in (name,seed):self.native.remove_repo(self.service,owner,repository,self.native.user)
        assert self.native.tree(self.service)==before
