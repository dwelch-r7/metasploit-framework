"""Runtime-bound native Gitea controls; no Framework request or payload helpers."""
import base64
import configparser
import json
import os
from pathlib import Path
import subprocess
import urllib.error
import urllib.request

ACCOUNTS = dict(line.split('=', 1) for line in Path('test/module_targets/gitea/accounts.env').read_text().splitlines())
PROFILES = {
    'legacy': ('1.12.6', '2.24.3', 'legacy', '/'),
    'vulnerable': ('1.16.6', '2.30.3', 'vulnerable', '/'),
    'fixed': ('1.16.7', '2.30.3', 'fixed', '/'),
    'locked': ('1.16.6', '2.30.3', 'locked', '/'),
    'blocked': ('1.16.6', '2.30.3', 'blocked', '/'),
    'prefix': ('1.16.6', '2.30.3', 'prefixed_backend', '/gitea/'),
}


class NativeGitea:
    def __init__(self):
        self.runtime = json.loads(Path(os.environ['MODULE_TARGET_RUNTIME']).read_text())
        self.compose = self.runtime['compose']
        self.artifacts = Path(self.runtime['artifacts'])
        self.records = {'commands': [], 'http': [], 'profiles': {}, 'proofs': []}
        self.admin = [ACCOUNTS['LAB_ADMIN'], ACCOUNTS['LAB_PASSWORD']]
        self.user = [ACCOUNTS['LAB_USER'], ACCOUNTS['LAB_PASSWORD']]

    def command(self, service, *arguments, user=None, expected=0, timeout=20):
        args = self.compose + ['exec', '-T'] + (['--user', user] if user else []) + [service] + list(arguments)
        result = subprocess.run(args, capture_output=True, timeout=timeout)
        row = {'service': service, 'argv': list(arguments), 'user': user, 'status': result.returncode,
               'stdout': result.stdout.decode('utf-8', 'backslashreplace'), 'stderr': result.stderr.decode('utf-8', 'backslashreplace'),
               'stdout_base64': base64.b64encode(result.stdout).decode(), 'stderr_base64': base64.b64encode(result.stderr).decode()}
        self.records['commands'].append(row)
        with (self.artifacts/'native-gitea-commands.jsonl').open('a') as output: output.write(json.dumps(row)+'\n')
        assert row['status'] == expected, row
        return row['stdout']

    def request(self, service, route, credentials=None, data=None, method=None, timeout=10):
        endpoint = self.runtime['endpoints'][service]
        prefix = PROFILES[service][3].rstrip('/') if service in PROFILES else ''
        url = 'http://'+endpoint['host']+':'+str(endpoint['port'])+prefix+route
        headers = {'Content-Type': 'application/json'} if data is not None else {}
        if credentials: headers['Authorization'] = 'Basic '+base64.b64encode(':'.join(credentials).encode()).decode()
        request = urllib.request.Request(url, headers=headers, data=json.dumps(data).encode() if data is not None else None, method=method)
        try: reply = urllib.request.urlopen(request, timeout=timeout)
        except urllib.error.HTTPError as error: reply = error
        body = reply.read()
        row = {'service': service, 'url': url, 'route': route, 'method': request.get_method(), 'credentials': credentials,
               'request': data, 'status': reply.status, 'headers': dict(reply.headers), 'body_base64': base64.b64encode(body).decode()}
        self.records['http'].append(row)
        with (self.artifacts/'native-gitea-http.jsonl').open('a') as output: output.write(json.dumps(row)+'\n')
        try: document = json.loads(body)
        except (UnicodeDecodeError, json.JSONDecodeError): document = body.decode('utf-8', 'backslashreplace')
        return reply.status, document

    def tree(self, service):
        actor = PROFILES[service][2]
        return sorted(self.command(actor, 'find', '/data/git/repositories', '-mindepth', '1', '-print').splitlines())

    def remove_repo(self, service, owner, name, credentials):
        route = '/api/v1/repos/'+owner+'/'+name
        status, document = self.request(service, route, credentials)
        if status == 200: assert self.request(service, route, credentials, method='DELETE')[0] == 204
        else: assert status == 404, (status, document)

    def identity(self, service):
        version, git_version, actor, target_uri = PROFILES[service]
        assert self.request(service, '/api/v1/version') == (200, {'version': version})
        assert self.request(service, '/api/v1/user')[0] == 401
        assert self.request(service, '/api/v1/user', [ACCOUNTS['LAB_ADMIN'], 'module-target-rejected'])[0] == 401
        users = {}
        for credentials, admin in [(self.admin, True), (self.user, False)]:
            status, document = self.request(service, '/api/v1/user', credentials)
            assert status == 200 and document['login'] == credentials[0] and document['is_admin'] is admin, document
            users[credentials[0]] = document
        uid = self.command(actor, 'id', user='git').strip();assert 'uid=1000(git)' in uid, uid
        assert ('Gitea version '+version+' ') in self.command(actor, 'gitea', '--version', user='git')
        assert self.command(actor, 'git', '--version', user='git').strip() == 'git version '+git_version
        tools = self.command(actor, 'sh', '-c', 'for tool in bash curl wget base64 chmod id stat; do command -v "$tool" || exit 1; done', user='git').splitlines()
        configuration=self.command(actor,'cat','/data/gitea/conf/app.ini',user='git')
        parsed=configparser.ConfigParser(interpolation=None);parsed.read_string('[DEFAULT]\n'+configuration)
        assert parsed.getboolean('security','DISABLE_GIT_HOOKS') is (service=='locked'),configuration
        assert parsed.getboolean('migrations','ALLOW_LOCALNETWORKS') is (service!='blocked'),configuration
        assert parsed['server']['ROOT_URL']==('http://prefix/gitea/' if service=='prefix' else 'http://'+service+':3000/'),configuration
        self.records['profiles'][service] = {'version': version, 'git_version': git_version, 'actor': actor, 'target_uri': target_uri, 'uid': uid, 'users': users, 'tools': tools, 'configuration':configuration}
        # Real API deletion leaves the user namespace directory. Establish it
        # natively before exact per-run repository restoration is measured.
        for credentials in [self.admin, self.user]:
            name = 'module-target-native-parent'
            assert self.request(service, '/api/v1/user/repos', credentials, {'name': name, 'auto_init': True})[0] == 201
            assert self.request(service, '/api/v1/repos/'+credentials[0]+'/'+name, credentials, method='DELETE')[0] == 204
        return self.records['profiles'][service]

    def grant(self, service, allowed):
        status, current = self.request(service, '/api/v1/user', self.user)
        assert status == 200 and current['is_admin'] is False, current
        body = {'source_id': 0, 'login_name': current['login'], 'email': current['email'], 'allow_git_hook': allowed}
        assert self.request(service, '/api/v1/admin/users/'+current['login'], self.admin, body, method='PATCH')[0] == 200
        status, after = self.request(service, '/api/v1/user', self.user)
        assert status == 200 and after['is_admin'] is False, after

    def hook(self, service, credentials, permitted, label):
        actor = PROFILES[service][2];owner = credentials[0]
        name = 'module-target-native-'+label;route = '/api/v1/repos/'+owner+'/'+name
        proof = '/tmp/module-target-native-hook';before = self.tree(service)
        self.command(actor, 'test', '!', '-e', proof)
        token = 'Native-Gitea-'+service+'-'+label
        script = '#!/bin/sh\n{ id; pwd; printf "'+token+'\\nSELF=%s PPID=%s\\n" "$$" "$PPID"; cat /proc/$$/status /proc/$PPID/status; } > '+proof+'\n'
        try:
            status, created = self.request(service, '/api/v1/user/repos', credentials, {'name': name, 'auto_init': True})
            assert status == 201 and created['default_branch'] == 'master', (status, created)
            status, document = self.request(service, route+'/hooks/git/post-receive', credentials, {'content': script}, method='PATCH')
            if permitted:
                assert status in (200, 204), (status, document)
                status, document = self.request(service, route+'/hooks/git/post-receive', credentials)
                assert status == 200 and document['content'] == script, (status, document)
                content = (token+'\n').encode()
                assert self.request(service, route+'/contents/native.txt', credentials, {'branch': 'master', 'message': token, 'content': base64.b64encode(content).decode()})[0] == 201
                actual = self.command(actor, 'cat', proof);owner_id = self.command(actor, 'stat', '-c', '%u:%g', proof).strip()
                assert token in actual and 'uid=1000(git)' in actual and 'Name:' in actual and owner_id == '1000:1000', actual
                committed = self.command(actor, 'git', '--git-dir', '/data/git/repositories/'+owner+'/'+name+'.git', 'show', 'master:native.txt', user='git')
                assert committed.encode() == content
                self.records['proofs'].append({'service': service, 'label': label, 'owner': owner_id, 'proof': actual, 'committed': committed})
            else:
                assert status == 403, (status, document)
                self.command(actor, 'test', '!', '-e', proof)
        finally:
            self.remove_repo(service, owner, name, credentials)
            self.command(actor, 'rm', '-f', proof)
        assert self.tree(service) == before

    def save(self, name):
        (self.artifacts/name).write_text(json.dumps(self.records, indent=2)+'\n')
