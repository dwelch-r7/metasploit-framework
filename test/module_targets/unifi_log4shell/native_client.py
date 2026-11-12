"""Native HTTPS, process and database observations; no Framework module invocation."""
import http.cookiejar
import json
from pathlib import Path
import ssl
import subprocess
import urllib.error
import urllib.request


class NativeUnifi:
    USERNAME = 'module-target-operator'
    PASSWORD = 'module-target-unifi-password'

    def __init__(self, runtime):
        self.runtime = runtime
        self.artifacts = Path(runtime['artifacts'])
        endpoint = runtime['endpoints']['target']
        self.base = 'https://{}:{}'.format(endpoint['host'], endpoint['port'])
        self.context = ssl._create_unverified_context()
        self.client = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()), urllib.request.HTTPSHandler(context=self.context))
        self.requests = []
        self.commands = []

    def request(self, path, data=None, session=False):
        headers = {'Content-Type':'application/json','X-Requested-With':'XMLHttpRequest'}
        request = urllib.request.Request(self.base + path, data=None if data is None else json.dumps(data).encode(), headers=headers)
        try:
            response = self.client.open(request, timeout=15) if session else urllib.request.urlopen(request, context=self.context, timeout=15)
        except urllib.error.HTTPError as error:
            response = error
        with response:
            body = response.read().decode(errors='replace')
            row = dict(path=path, request=data, session_client=session, status=response.status, final_url=response.url, body=body)
            self.requests.append(row)
            return row

    def command(self, service, *arguments):
        command = self.runtime['compose'] + ['exec','-T',service] + list(arguments)
        result = subprocess.run(command,capture_output=True,text=True,timeout=30)
        record = dict(argv=command,exitstatus=result.returncode,stdout=result.stdout,stderr=result.stderr)
        self.commands.append(record)
        assert result.returncode == 0, record
        return result.stdout

    def mongo(self, expression):
        raw = self.command('target','mongo','--quiet','--port','27117','ace','--eval','JSON.stringify(' + expression + ')')
        return json.loads(raw)

    def setup(self):
        admins = self.mongo('db.admin.count()')
        assert admins == 0
        response = self.request('/api/cmd/sitemgr',dict(cmd='add-default-admin',name=self.USERNAME,email='module-target@example.invalid',x_password=self.PASSWORD),session=True)
        assert response['status']==200 and json.loads(response['body'])['meta']['rc']=='ok',response
        response = self.request('/api/login',dict(username=self.USERNAME,password=self.PASSWORD,remember=False,strict=True),session=True)
        assert response['status']==200 and json.loads(response['body'])['meta']['rc']=='ok',response
        for path,data in [('/api/set/setting/super_identity',{'name':'Module target UniFi'}),('/api/set/setting/country',{'code':840}),('/api/set/setting/locale',{'timezone':'UTC'}),('/api/set/setting/super_mgmt',{'autobackup_enabled':False,'backup_to_cloud_enabled':False}),('/api/cmd/system',{'cmd':'set-installed'})]:
            response = self.request(path,data,session=True)
            assert response['status']==200 and json.loads(response['body'])['meta']['rc']=='ok',response
        response = self.request('/api/self',session=True)
        assert response['status']==200 and json.loads(response['body'])['data'][0]['name']==self.USERNAME,response
        response = self.request('/api/logout',{},session=True)
        assert response['status']==200 and json.loads(response['body'])['meta']['rc']=='ok',response
        response = self.request('/api/self')
        assert response['status'] in [400,401] and json.loads(response['body'])['meta']['msg']=='api.err.LoginRequired',response
        response = self.request('/')
        assert response['status']==200 and ('/manage' in response['final_url'] or '/manage/' in response['body']) and '<base href="/setup/"' not in response['body'],response
        response = self.request('/api/login',dict(username=self.USERNAME,password='module-target-wrong-password',remember=False,strict=True))
        assert response['status']==400 and json.loads(response['body'])['meta']['msg']=='api.err.Invalid',response
        assert self.mongo('db.admin.count()')==1

    def trigger(self, remember):
        response = self.request('/api/login',dict(username=self.USERNAME,password='module-target-wrong-password',remember=remember,strict=True))
        assert response['status']==400 and json.loads(response['body'])['meta']['msg']=='api.err.InvalidPayload',response
        return response

    def identities(self):
        return [json.loads(line) for line in self.command('target','cat','/unifi/proofs/jvm-identity.jsonl').splitlines()]

    def write(self, proof):
        (self.artifacts/'native-unifi.json').write_text(json.dumps(dict(proof=proof,requests=self.requests,commands=self.commands),indent=2)+'\n')
