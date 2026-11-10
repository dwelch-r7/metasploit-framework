"""Independent Gogs/real-Git controls. No Framework request or payload helper."""
import base64
import configparser
import csv
import hashlib
import http.cookiejar
from html.parser import HTMLParser
import json
import os
from pathlib import Path
import re
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request

ROOT = Path(__file__).resolve().parent
REPOSITORIES = '/data/git/gogs-repositories'
EXPECTED_COMMITS = {'0.14.2': '5dcb6c64bdf61e38dbdbb941c1d69789c560d0fb',
                    '0.14.3': '3ba8aca90e17e5410b7e8b227c9f29256ac3e875'}
ZERO_QUOTA_MESSAGE = 'user has reached maximum limit of repositories [limit: 0]'
REDACTED_ERROR_MESSAGE = 'Something went wrong, please check the server logs for more information.'
QUOTA_RESPONSE_MESSAGES = {'0.12.3': ZERO_QUOTA_MESSAGE,
                           '0.14.2': REDACTED_ERROR_MESSAGE,
                           '0.14.3': REDACTED_ERROR_MESSAGE}
TOKEN_LIST_KINDS = {'0.12.3': 'legacy-raw-token',
                    '0.14.2': 'stored-sha256-prefix40',
                    '0.14.3': 'stored-sha256-prefix40'}




class Fields(HTMLParser):
    def __init__(self, content):
        super().__init__()
        self.inputs = []
        self.links = []
        self.feed(content)

    def handle_starttag(self, tag, attributes):
        if tag == 'input':
            self.inputs.append(dict(attributes))
        elif tag == 'a':
            self.links.append(dict(attributes).get('href', ''))

    def value(self, name):
        return next(row['value'] for row in self.inputs if row.get('name') == name or row.get('id') == name)


class TokenRows(HTMLParser):
    """Parse the tagged settings item rows without inferring IDs from order."""
    def __init__(self, content, delete_path):
        super().__init__()
        self.rows = []
        self.depth = 0
        self.current = None
        self.in_name = False
        self.delete_path = delete_path
        self.feed(content)
        assert self.current is None and self.depth == 0, 'Incomplete token settings HTML'

    def handle_starttag(self, tag, attributes):
        attrs = dict(attributes)
        if tag == 'div':
            self.depth += 1
            if {'item', 'ui', 'grid'} <= set(attrs.get('class', '').split()):
                assert self.current is None, 'Nested token rows are ambiguous'
                self.current = {'depth': self.depth, 'name_parts': [], 'ids': []}
        if self.current is not None:
            if tag == 'strong':
                assert not self.in_name, 'Nested token names are ambiguous'
                self.in_name = True
            elif tag == 'button' and 'delete-button' in attrs.get('class', '').split():
                assert urllib.parse.urlsplit(attrs.get('data-url', '')).path == self.delete_path, attrs
                assert re.fullmatch('[1-9][0-9]*', attrs.get('data-id', '')), attrs
                self.current['ids'].append(int(attrs['data-id']))

    def handle_data(self, content):
        if self.current is not None and self.in_name:
            self.current['name_parts'].append(content)

    def handle_endtag(self, tag):
        if tag == 'strong':
            self.in_name = False
        if tag == 'div':
            if self.current is not None and self.depth == self.current['depth']:
                name = ''.join(self.current['name_parts'])
                assert name and len(self.current['ids']) == 1, self.current
                self.rows.append({'name': name, 'id': self.current['ids'][0]})
                self.current = None
            self.depth -= 1
            assert self.depth >= 0, 'Unbalanced token settings HTML'


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *_arguments):
        return None


class NativeGogs:
    def __init__(self):
        self.runtime = json.loads(Path(os.environ['MODULE_TARGET_RUNTIME']).read_text())
        self.artifacts = Path(self.runtime['artifacts'])
        family = os.environ['GOGS_TARGET_PROFILE']
        self.profile = json.loads(Path('test/module_targets', family, 'profile.json').read_text())
        self.services = self.profile['services']
        self.compose = self.runtime['compose']
        self.accounts = {row['username']: row for row in csv.DictReader((ROOT/'accounts.tsv').open(), delimiter='\t')}
        self.token_path = self.artifacts/'native-gogs-tokens.json'
        self.tokens = json.loads(self.token_path.read_text()) if self.token_path.exists() else {}
        self.records = {'commands': [], 'http': [], 'identities': {}, 'proofs': []}

    def record(self, kind, row):
        self.records[kind].append(row)
        with (self.artifacts/f'native-gogs-{kind}.jsonl').open('a') as output:
            output.write(json.dumps(row)+'\n')

    def command(self, actor, *arguments, expected=0, user=None, timeout=20, stdin=None):
        argv = self.compose+['exec', '-T']+(['--user', user] if user else [])+[actor]+list(arguments)
        started = time.monotonic()
        result = subprocess.run(argv, input=stdin, capture_output=True, timeout=timeout)
        row = {'actor': actor, 'argv': list(arguments), 'user': user, 'exitstatus': result.returncode,
               'seconds': time.monotonic()-started, 'stdout_base64': base64.b64encode(result.stdout).decode(),
               'stderr_base64': base64.b64encode(result.stderr).decode()}
        self.record('commands', row)
        assert result.returncode == expected, row
        return result.stdout.decode('utf-8')

    def frame(self, *arguments, expected=0, timeout=20):
        return self.command('framework', *arguments, user=f'{os.getuid()}:{os.getgid()}', expected=expected, timeout=timeout)

    def service_logs(self, service, deadline=None):
        """Read only this actor's actual Docker logs; retain each raw channel."""
        actor = self.services[service]['actor']

        def observe(argv):
            remaining = 10 if deadline is None else deadline-time.monotonic()
            assert remaining > 0, 'Quota log observation exceeded its 3-second deadline'
            started = time.monotonic()
            try:
                result = subprocess.run(argv, capture_output=True, timeout=min(10, remaining))
                stdout, stderr, status = result.stdout, result.stderr, result.returncode
                failure = None
            except subprocess.TimeoutExpired as error:
                stdout, stderr, status = error.stdout or b'', error.stderr or b'', None
                failure = repr(error)
            row = {'actor': actor, 'execution': 'owned-host-log-observation', 'argv': argv,
                   'seconds': time.monotonic()-started, 'exitstatus': status, 'failure': failure,
                   'stdout_base64': base64.b64encode(stdout).decode(),
                   'stderr_base64': base64.b64encode(stderr).decode()}
            self.record('commands', row)
            assert status == 0, row
            return stdout, stderr

        output, _error = observe(self.compose+['ps', '--quiet', actor])
        identifiers = output.decode().split()
        assert len(identifiers) == 1 and re.fullmatch('[a-f0-9]{12,64}', identifiers[0]), identifiers
        stdout, stderr = observe(['docker', 'logs', '--timestamps', identifiers[0]])
        return {'container_id': identifiers[0], 'stdout': stdout, 'stderr': stderr}

    def quota_log_proof(self, service, before):
        """Require one new typed operation from the same unchanged log streams."""
        began = time.monotonic()
        deadline = began+3
        expected = ('create repository: '+ZERO_QUOTA_MESSAGE).encode()
        while True:
            after = self.service_logs(service, deadline=deadline)
            prefixes = {channel: after[channel].startswith(before[channel]) for channel in ['stdout', 'stderr']}
            operations = []
            if all(prefixes.values()):
                for channel in ['stdout', 'stderr']:
                    delta = after[channel][len(before[channel]):]
                    operations += [line for line in delta.splitlines()
                                   if b'[ERROR]' in line and b'create repository: ' in line]
            row = {'service': service, 'before_container': before['container_id'],
                   'after_container': after['container_id'], 'seconds': time.monotonic()-began,
                   'prefixes_preserved': prefixes,
                   'before_sizes': {key: len(before[key]) for key in ['stdout', 'stderr']},
                   'after_sizes': {key: len(after[key]) for key in ['stdout', 'stderr']},
                   'new_operations': [line.decode('utf-8', 'backslashreplace') for line in operations]}
            self.records.setdefault('quota_log_observations', [])
            self.record('quota_log_observations', row)
            assert before['container_id'] == after['container_id'] and all(prefixes.values()), row
            assert len(operations) <= 1, row
            if operations:
                assert operations[0].endswith(expected), row
                return operations[0].decode('utf-8', 'backslashreplace')
            remaining = deadline-time.monotonic()
            assert remaining > 0, row
            time.sleep(min(0.05, remaining))

    def origin(self, service, internal=False):
        definition = self.services[service]
        key = 'module_endpoints' if internal else 'endpoints'
        endpoint = self.runtime[key][definition['endpoint']]
        return 'http://'+endpoint['host']+':'+str(endpoint['port'])+definition['prefix']

    def request(self, service, route, *, user=None, data=None, method=None, basic=False, token=None):
        headers = {'Content-Type': 'application/json'} if data is not None else {}
        if user:
            if basic:
                secret = user+':'+self.accounts[user]['password']
                headers['Authorization'] = 'Basic '+base64.b64encode(secret.encode()).decode()
            else:
                headers['Authorization'] = 'token '+self.token(service, user)
        if token:
            headers['Authorization'] = 'token '+token
        request = urllib.request.Request(self.origin(service)+route, headers=headers,
                                         data=json.dumps(data).encode() if data is not None else None, method=method)
        try:
            response = urllib.request.urlopen(request, timeout=10)
        except urllib.error.HTTPError as error:
            response = error
        body = response.read()
        row = {'service': service, 'url': request.full_url, 'method': request.get_method(), 'user': user,
               'basic': basic, 'request': data, 'status': response.status, 'headers': dict(response.headers),
               'body_base64': base64.b64encode(body).decode()}
        if headers.get('Authorization', '').startswith('token '):
            row['submitted_token_sha256'] = hashlib.sha256(headers['Authorization'][6:].encode()).hexdigest()
        self.record('http', row)
        try:
            document = json.loads(body)
        except (ValueError, UnicodeDecodeError):
            document = body.decode('utf-8', 'backslashreplace')
        return response.status, document

    def token(self, service, user):
        key = service+':'+user
        if key not in self.tokens:
            name = 'module-target-native-'+user
            status, document = self.request(service, '/api/v1/users/'+user+'/tokens', user=user, basic=True,
                                             data={'name': name}, method='POST')
            assert status == 201 and re.fullmatch('[a-f0-9]{40}', document['sha1']), (status, document)
            self.tokens[key] = document['sha1']
            self.token_path.write_text(json.dumps(self.tokens, indent=2))
        return self.tokens[key]

    def list_tokens(self, service, user):
        """Normalize actual settings IDs; they are not fields of the API DTO."""
        status, rows = self.request(service, '/api/v1/users/'+user+'/tokens', user=user, basic=True)
        assert status == 200 and isinstance(rows, list), (status, rows)
        for row in rows:
            assert set(row) == {'name', 'sha1'} and isinstance(row['name'], str), row
            assert re.fullmatch('[a-f0-9]{40}', row['sha1']), row
        api_names = [row['name'] for row in rows]
        assert len(api_names) == len(set(api_names)), 'Duplicate API token names are ambiguous'
        ui = NativeUI(self, service)
        ui.login(user)
        status, body, _fields = ui.request('/user/settings/applications')
        assert status == 200, status
        delete_path = self.services[service]['prefix']+'/user/settings/applications/delete'
        visible = TokenRows(body, delete_path).rows
        assert len({row['name'] for row in visible}) == len(visible), visible
        assert len({row['id'] for row in visible}) == len(visible), visible
        assert set(api_names) == {row['name'] for row in visible}, (rows, visible)
        identifiers = {row['name']: row['id'] for row in visible}
        provenance = {'kind': 'authenticated-settings-row-data-id', 'user': user,
                      'url': self.origin(service)+'/user/settings/applications'}
        normalized = [{'name': row['name'], 'sha1': row['sha1'], 'api_fields': row,
                       'id': identifiers[row['name']], 'id_source': provenance,
                       'api_sha1_kind': TOKEN_LIST_KINDS[self.services[service]['version']]} for row in rows]
        return sorted(normalized, key=lambda row: row['id'])

    def token_state_summary(self, rows):
        """Summarize token state without printing API values or credentials."""
        return [{'name': row['name'], 'id': row['id'], 'id_source': row['id_source'],
                 'api_sha1_kind': row['api_sha1_kind'],
                 'api_value_sha256': hashlib.sha256(row['sha1'].encode()).hexdigest()} for row in rows]

    def edit_user(self, service, user, **changes):
        status, current = self.request(service, '/api/v1/user', user=user)
        assert status == 200 and current['login'] == user, (status, current)
        ui = NativeUI(self, service)
        ui.login('lab-admin')
        before = ui.account_state(current['id'])
        # All fixture accounts are local. Do not confuse API login/username with
        # an external authentication source's actual LoginName.
        assert before['login_type'] == '0-0' and not before['admin'], before
        body = {name: before[name] for name in ['login_name', 'full_name', 'email', 'website', 'location']}
        body.update(source_id=int(before['login_type'].split('-')[1]), **changes)
        status, document = self.request(service, '/api/v1/admin/users/'+user, user='lab-admin', data=body, method='PATCH')
        assert status == 200 and document['id'] == current['id'], (status, document)
        after = ui.account_state(current['id'])
        assert after == {**before, **changes}, (before, changes, after)
        self.records['proofs'].append({'kind': 'native-account-setting', 'service': service, 'user': user,
                                      'before': before, 'requested': changes, 'after': after})

    def create_repo(self, service, user, name, branch='master'):
        status, document = self.request(service, '/api/v1/user/repos', user=user,
                                       data={'name': name, 'private': True, 'default_branch': branch, 'auto_init': False})
        assert status == 201 and document['name'] == name, (status, document)
        return document

    def remove_repo(self, service, owner, name):
        route = '/api/v1/repos/'+owner+'/'+name
        status, _document = self.request(service, route, user=owner)
        if status == 200:
            status, document = self.request(service, route, user=owner, method='DELETE')
            assert status == 204, (status, document)
        else:
            assert status == 404, (status, _document)
        assert self.request(service, route, user=owner)[0] == 404

    def repo_tree(self, service):
        actor = self.services[service]['actor']
        return sorted(self.command(actor, 'find', REPOSITORIES, '-mindepth', '1', '-print').splitlines())

    def refs(self, service, owner, name):
        actor = self.services[service]['actor']
        path = REPOSITORIES+'/'+owner+'/'+name.lower()+'.git'
        return self.command(actor, 'git', '--git-dir', path, 'for-each-ref', '--format=%(refname) %(objectname)', user='git').splitlines()

    def clone_url(self, service, owner, name, user):
        origin = urllib.parse.urlsplit(self.origin(service, internal=True))
        credentials = urllib.parse.quote(user, safe='')+':'+urllib.parse.quote(self.accounts[user]['password'], safe='')
        return urllib.parse.urlunsplit((origin.scheme, credentials+'@'+origin.netloc, origin.path+'/'+owner+'/'+name+'.git', '', ''))

    def git(self, directory, *arguments, expected=0):
        return self.frame('env', 'GIT_TERMINAL_PROMPT=0', 'GIT_AUTHOR_DATE=2001-01-01T00:00:00Z', 'GIT_COMMITTER_DATE=2001-01-01T00:00:00Z', 'git', '-C', directory, *arguments, expected=expected)

    def working_copy(self, service, owner, name, user, *, clone=True, branch='master'):
        directory = self.frame('mktemp', '-d', '/tmp/native-gogs-XXXXXX').strip()
        url = self.clone_url(service, owner, name, user)
        if clone:
            self.frame('env', 'GIT_TERMINAL_PROMPT=0', 'git', 'clone', url, directory)
        else:
            self.frame('git', 'init', directory)
            self.git(directory, 'symbolic-ref', 'HEAD', 'refs/heads/'+branch)
            self.git(directory, 'remote', 'add', 'origin', url)
        self.git(directory, 'config', 'user.name', 'Module target native')
        self.git(directory, 'config', 'user.email', 'native@gogs.invalid')
        return directory

    def write(self, directory, name, content):
        script = 'from pathlib import Path;import sys;Path(sys.argv[1]).write_bytes(bytes.fromhex(sys.argv[2]))'
        self.frame('python3', '-c', script, directory+'/'+name, content.encode().hex())

    def commit(self, directory, label):
        self.git(directory, 'add', '.')
        self.git(directory, '-c', 'commit.gpgsign=false', 'commit', '-m', label)
        return self.git(directory, 'rev-parse', 'HEAD').strip()

    def seed(self, service, name, *, rebase=True):
        self.remove_repo(service, 'lab-admin', name)
        self.create_repo(service, 'lab-admin', name, branch='main')
        directory = self.working_copy(service, 'lab-admin', name, 'lab-admin', clone=False, branch='main')
        try:
            self.write(directory, 'README.md', 'Module target existing repository\n')
            self.commit(directory, 'Native seed')
            self.git(directory, 'push', '-u', 'origin', 'main')
        finally:
            self.frame('rm', '-rf', directory)
        status, repository = self.request(service, '/api/v1/repos/lab-admin/'+name, user='lab-admin')
        assert status == 200 and repository['default_branch'] == 'main', (status, repository)
        ui = NativeUI(self, service)
        ui.login('lab-admin')
        ui.set_rebase('lab-admin', name, rebase)
        for user, permission in [('lab-writer', 'write'), ('lab-reader', 'read')]:
            status, document = self.request(service, '/api/v1/repos/lab-admin/'+name+'/collaborators/'+user,
                                             user='lab-admin', data={'permission': permission}, method='PUT')
            assert status in (200, 204), (status, document)
        return {'owner': 'lab-admin', 'name': name, 'refs': self.refs(service, 'lab-admin', name), 'rebase': rebase}

    def identity(self, service):
        definition = self.services[service]
        actor = definition['actor']
        version = self.command(actor, '/app/gogs/gogs', '--version', user='git').strip()
        assert re.search(r'\b'+re.escape(definition['version'])+r'\b', version), version
        help_text = self.command(actor, '/app/gogs/gogs', 'admin', 'create-user', '--help', user='git')
        assert '--name' in help_text and '--config' in help_text, help_text
        config = self.command(actor, 'cat', '/data/gogs/conf/app.ini', user='git')
        parsed = configparser.ConfigParser(interpolation=None)
        parsed.read_string('[DEFAULT]\n'+config)
        assert parsed['database']['TYPE'] == 'sqlite3' and parsed['server']['EXTERNAL_URL'] == definition['external_url'], config
        assert parsed.getboolean('server', 'DISABLE_SSH') and not parsed.getboolean('repository', 'DISABLE_HTTP_GIT')
        uid = self.command(actor, 'id', user='git').strip()
        assert 'uid=1000(git)' in uid, uid
        tools = self.command(actor, 'sh', '-c', 'for t in bash curl git base64 chmod stat; do command -v "$t" || exit 1; done', user='git')
        status, body = self.request(service, '/')
        assert status == 200 and re.search(r'<meta\s+name="author"\s+content="Gogs"', body), (status, body)
        static_hash = re.search(r'gogs\.min\.css\?v=([a-f0-9]{40})', body)
        if definition['version'] in EXPECTED_COMMITS:
            assert static_hash and static_hash[1] == EXPECTED_COMMITS[definition['version']], body
        # Native tokens are explicit baseline fixture state, not module leftovers.
        users = {}
        for user in self.accounts:
            status, identity = self.request(service, '/api/v1/user', user=user)
            assert status == 200 and identity['login'] == user, (status, identity)
            users[user] = identity
        # Both tagged API routers lack GET /admin/users. Use the real read-only
        # web users page: the native admin sees all six IDs; signed-in ordinary
        # users are rejected by context.Toggle(AdminRequired) with403.
        for user, expected_status in [('lab-admin', 200), ('lab-user', 403)]:
            ui = NativeUI(self, service)
            ui.login(user)
            status, _body, fields = ui.request('/admin/users')
            assert status == expected_status, (service, user, status)
            if expected_status == 200:
                pattern = re.escape(definition['prefix'])+r'/admin/users/(\d+)'
                observed_ids = {int(match[1]) for link in fields.links
                                if (match := re.fullmatch(pattern, urllib.parse.urlsplit(link).path))}
                assert observed_ids == {row['id'] for row in users.values()}, observed_ids
            code, unchanged = self.request(service, '/api/v1/user', user=user)
            assert code == 200 and unchanged == users[user], (code, unchanged, users[user])
            self.records['proofs'].append({'kind': 'native-read-only-admin-role', 'service': service,
                                          'user': user, 'status': status, 'self_profile_unchanged': True})
        bad = self.accounts['lab-user']['password']
        self.accounts['lab-user']['password'] = 'public-wrong-password'
        try:
            assert self.request(service, '/api/v1/users/lab-user/tokens', user='lab-user', basic=True, data={'name': 'must-not-exist'}, method='POST')[0] == 401
        finally:
            self.accounts['lab-user']['password'] = bad
        # Reuse the qualified Gitea native pattern: establish real account
        # namespaces through API create/delete before exact restoration checks.
        # Preserve the genuine residual tree rather than deleting parent dirs.
        before_namespaces = self.repo_tree(service)
        for user in ['lab-admin', 'lab-user', 'lab-hook']:
            self.create_repo(service, user, 'module-target-native-namespace')
            self.remove_repo(service, user, 'module-target-native-namespace')
        self.records['proofs'].append({'kind': 'native-account-namespaces', 'service': service,
                                      'before': before_namespaces, 'after': self.repo_tree(service)})
        self.edit_user(service, 'lab-hook', allow_git_hook=True)
        self.edit_user(service, 'lab-writer', max_repo_creation=0)
        ui = NativeUI(self, service)
        ui.login('lab-admin')
        quota_before = ui.account_state(users['lab-writer']['id'])
        assert quota_before['max_repo_creation'] == 0, quota_before
        code, repositories_before = self.request(service, '/api/v1/user/repos', user='lab-writer')
        assert code == 200 and repositories_before == [], (code, repositories_before)
        # Both tagged CreateUserRepo handlers use the generic 500 path for this
        # typed policy refusal. An arbitrary500 is never a successful control.
        logs_before = self.service_logs(service)
        status, document = self.request(service, '/api/v1/user/repos', user='lab-writer', data={'name': 'quota-must-not-exist'})
        expected_message = QUOTA_RESPONSE_MESSAGES[definition['version']]
        assert status == 500 and isinstance(document, dict) and document.get('message') == expected_message, (status, document)
        operation_log = self.quota_log_proof(service, logs_before)
        code, repositories_after = self.request(service, '/api/v1/user/repos', user='lab-writer')
        assert code == 200 and repositories_after == repositories_before, (code, repositories_before, repositories_after)
        assert self.request(service, '/api/v1/repos/lab-writer/quota-must-not-exist', user='lab-writer')[0] == 404
        code, profile_after = self.request(service, '/api/v1/user', user='lab-writer')
        assert code == 200 and profile_after == users['lab-writer'], (code, profile_after)
        quota_after = ui.account_state(users['lab-writer']['id'])
        assert quota_after == quota_before, (quota_before, quota_after)
        self.records['proofs'].append({'kind': 'native-zero-quota-refusal', 'service': service, 'status': status,
                                      'message': document['message'], 'new_typed_operation': operation_log, 'repositories_before': repositories_before,
                                      'repositories_after': repositories_after, 'before': quota_before, 'after': quota_after})
        self.records['identities'][service] = {'version': version, 'git': self.command(actor, 'git', '--version', user='git'),
                                               'uid': uid, 'configuration': config, 'tools': tools, 'users': users,
                                               'asset_hash': static_hash[1] if static_hash else None}
        return users

    def elf_control(self, services):
        binary = '/tmp/native-gogs-elf'
        source = '/usr/src/metasploit-framework/test/module_targets/gogs/native_elf.c'
        assert self.frame('id', '-u').strip() == str(os.getuid())
        self.frame('sh', '-c', 'printf \"FRAMEWORK_HOME=%s\\n\" \"$HOME\"')
        self.frame('git', '--version')
        directory = self.frame('mktemp', '-d', '/tmp/native-gogs-default-XXXXXX').strip()
        try:
            self.frame('git', 'init', directory)
            branch = self.git(directory, 'symbolic-ref', '--short', 'HEAD').strip()
            self.records['proofs'].append({'kind': 'actual-framework-default-git-branch', 'branch': branch})
        finally:
            self.frame('rm', '-rf', directory)
        self.frame('cc', '--version')
        self.frame('cc', '-static', '-O0', source, '-o', binary)
        local = self.artifacts/'native-gogs-elf'
        result = subprocess.run(self.compose+['cp', 'framework:'+binary, str(local)], capture_output=True, timeout=15)
        assert result.returncode == 0, result.stderr
        data = local.read_bytes()
        assert data[:5] == b'\x7fELF\x02' and data[18:20] == b'\x3e\x00', data[:20].hex()
        try:
            for service in services:
                actor = self.services[service]['actor']
                result = subprocess.run(self.compose+['cp', str(local), actor+':'+binary], capture_output=True, timeout=15)
                assert result.returncode == 0, result.stderr
                self.command(actor, 'chmod', '755', binary)
                output = self.command(actor, binary, user='git')
                assert output == 'MODULE_TARGET_NATIVE_ELF uid=1000 gid=1000\n', output
                self.command(actor, 'rm', '-f', binary)
                self.records['proofs'].append({'kind': 'native-static-x64-elf', 'service': service, 'sha256': hashlib.sha256(data).hexdigest(), 'output': output})
        finally:
            self.frame('rm', '-f', binary)

    def hook_control(self, service, user, permitted):
        ui = NativeUI(self, service)
        ui.login(user)
        name = 'native-hook-'+user
        proof = '/tmp/native-gogs-hook-'+user
        before = self.repo_tree(service)
        try:
            ui.create_repo(name)
            status, _body, fields = ui.request('/'+user+'/'+name+'/settings/hooks/git/post-receive')
            if not permitted:
                assert status == 404, status
                self.command(self.services[service]['actor'], 'test', '!', '-e', proof)
            else:
                assert status == 200, status
                script = '#!/bin/bash\n{ id; printf "NATIVE_GOGS_HOOK PID=%s PPID=%s\\n" "$$" "$PPID"; } > '+proof+'\n'
                assert ui.request('/'+user+'/'+name+'/settings/hooks/git/post-receive', {'_csrf': fields.value('_csrf'), 'content': script})[0] == 302
                status, _body, fields = ui.request('/'+user+'/'+name+'/_new/master')
                assert status == 200, status
                assert ui.request('/'+user+'/'+name+'/_new/master', {'_csrf': fields.value('_csrf'), 'last_commit': fields.value('last_commit'), 'tree_path': 'native.txt', 'content': 'Native real editor\n', 'commit_summary': 'Native proof', 'commit_choice': 'direct'})[0] == 302
                actor = self.services[service]['actor']
                output = self.command(actor, 'cat', proof)
                assert 'uid=1000(git)' in output and 'NATIVE_GOGS_HOOK PID=' in output, output
                committed = self.command(actor, 'git', '--git-dir', REPOSITORIES+'/'+user+'/'+name+'.git', 'show', 'master:native.txt', user='git')
                assert committed == 'Native real editor\n', committed
                self.records['proofs'].append({'kind': 'native-web-hook', 'service': service, 'user': user, 'output': output, 'committed': committed})
            ui.delete_repo(user, name)
        finally:
            self.remove_repo(service, user, name)
            self.command(self.services[service]['actor'], 'rm', '-f', proof)
        assert self.repo_tree(service) == before

    def rebase_control(self, service, *, enabled=True, expected_execution=True, user='lab-user'):
        name = 'native-rebase-'+user
        proof = '/tmp/native-gogs-rebase-'+user
        self.remove_repo(service, user, name)
        self.create_repo(service, user, name)
        directory = self.working_copy(service, user, name, user, clone=False)
        ui = NativeUI(self, service)
        ui.login(user)
        try:
            self.write(directory, 'README.md', 'Native base\n')
            self.commit(directory, 'Native base')
            self.git(directory, 'push', '-u', 'origin', 'master')
            ui.set_rebase(user, name, enabled)
            self.git(directory, 'checkout', '-b', 'native-feature')
            self.write(directory, 'feature.txt', 'Native feature\n')
            self.commit(directory, 'Native feature')
            self.git(directory, 'push', 'origin', 'native-feature')
            self.git(directory, 'checkout', 'master')
            self.write(directory, 'diverge.txt', 'Native divergence\n')
            self.commit(directory, 'Native divergence')
            command = 'printf NATIVE_GOGS_REBASE>'+proof+';id>>'+proof
            for padding in range(51):
                encoded = base64.b64encode((' '*padding+command).encode()).decode()
                if '//' not in encoded:
                    break
            else:
                raise AssertionError('Native command cannot form a safe Git ref')
            branch = '--exec=echo${IFS}'+encoded+'|base64${IFS}-d|sh'
            assert max(len(part.encode()) for part in branch.split('/')) <= 255, branch
            self.git(directory, 'check-ref-format', 'refs/heads/'+branch)
            self.git(directory, 'push', 'origin', 'HEAD:refs/heads/'+branch)
            number = ui.create_pr(user, name, branch, 'native-feature')
            merge = ui.merge(user, name, number)
            actor = self.services[service]['actor']
            if expected_execution:
                output = self.command(actor, 'cat', proof)
                assert output.startswith('NATIVE_GOGS_REBASE') and 'uid=1000(git)' in output, output
            else:
                self.command(actor, 'test', '!', '-e', proof)
                output = None
            self.records['proofs'].append({'kind': 'native-rebase', 'service': service, 'enabled': enabled, 'branch': branch,
                                          'number': number, 'merge_status': merge, 'expected_execution': expected_execution, 'output': output,
                                          'refs': self.refs(service, user, name)})
        finally:
            self.frame('rm', '-rf', directory)
            self.remove_repo(service, user, name)
            self.command(self.services[service]['actor'], 'rm', '-f', proof)

    def git_exec_control(self, service):
        actor = self.services[service]['actor']
        directory = self.command(actor, 'mktemp', '-d', '/tmp/native-gogs-git-XXXXXX', user='git').strip()
        proof = directory+'/exec-proof'
        def git(*arguments):
            return self.command(actor, 'git', '-C', directory, *arguments, user='git')
        try:
            self.command(actor, 'git', 'init', directory, user='git')
            git('symbolic-ref', 'HEAD', 'refs/heads/main')
            git('config', 'user.name', 'Native git control')
            git('config', 'user.email', 'native@gogs.invalid')
            self.command(actor, 'sh', '-c', 'printf base > "$1/base.txt"', 'sh', directory, user='git')
            git('add', '.')
            git('commit', '-m', 'Base')
            git('checkout', '-b', 'native-feature')
            self.command(actor, 'sh', '-c', 'printf feature > "$1/feature.txt"', 'sh', directory, user='git')
            git('add', '.')
            git('commit', '-m', 'Feature')
            git('checkout', 'main')
            self.command(actor, 'sh', '-c', 'printf diverge > "$1/diverge.txt"', 'sh', directory, user='git')
            git('add', '.')
            git('commit', '-m', 'Diverge')
            git('checkout', 'native-feature')
            git('rebase', '--exec', 'printf NATIVE_GIT_EXEC > '+proof, 'main')
            assert self.command(actor, 'cat', proof, user='git') == 'NATIVE_GIT_EXEC'
            self.records['proofs'].append({'kind': 'native-git-exec-supported', 'service': service})
        finally:
            self.command(actor, 'rm', '-rf', directory, user='git')

    def access_controls(self, service):
        name = 'native-access-control'
        seed = self.seed(service, name)
        try:
            for user, expected in [('lab-writer', 0), ('lab-reader', 1)]:
                directory = self.working_copy(service, 'lab-admin', name, user)
                try:
                    self.git(directory, 'checkout', '-b', 'native-'+user)
                    self.write(directory, 'access.txt', 'Native '+user+'\n')
                    self.commit(directory, 'Native access')
                    if expected == 0:
                        self.git(directory, 'push', 'origin', 'HEAD:refs/heads/native-'+user)
                    else:
                        # The actual Git status is recorded;128 is the ordinary
                        # HTTP authorization failure contract to validate live.
                        self.git(directory, 'push', 'origin', 'HEAD:refs/heads/native-'+user, expected=128)
                finally:
                    self.frame('rm', '-rf', directory)
            assert self.request(service, '/api/v1/repos/lab-admin/'+name, user='lab-outsider')[0] == 404
            self.records['proofs'].append({'kind': 'native-collaborator-access', 'service': service, 'seed': seed})
        finally:
            self.remove_repo(service, 'lab-admin', name)

    def processes(self, service):
        # Shell is the sole observer; skip its PID and capture original stat bytes.
        script = 'for f in /proc/[0-9]*/stat; do p=${f#/proc/}; p=${p%/stat}; test \"$p\" = \"$$\" && continue; test -r \"$f\" || continue; IFS= read -r row < \"$f\" || continue; printf \"%s\\n\" \"$row\"; done'
        return sorted(self.command(self.services[service]['actor'], 'sh', '-c', script).splitlines())

    def state(self, service):
        actor = self.services[service]['actor']
        repos = {}
        for user in self.accounts:
            status, rows = self.request(service, '/api/v1/user/repos', user=user)
            assert status == 200 and isinstance(rows, list), (status, rows)
            repos[user] = sorted(rows, key=lambda row: row['name'])
        script = 'if test -d /data/gogs/data/tmp; then find /data/gogs/data/tmp -mindepth 1 -print; fi'
        app_tmp = sorted(self.command(actor, 'sh', '-c', script).splitlines())
        return {'repositories': repos, 'tree': self.repo_tree(service), 'app_tmp': app_tmp,
                'tokens': {user: self.list_tokens(service, user) for user in self.accounts},
                'target_tmp': sorted(self.command(actor, 'find', '/tmp', '-mindepth', '1', '-print').splitlines()),
                'processes': self.processes(service),
                'framework_tmp': sorted(self.frame('find', '/tmp', '-maxdepth', '1', '-name', 'msf_gogs_*', '-print').splitlines())}

    def revoke_new_tokens(self, service, user, before):
        old_ids = {row['id'] for row in before}
        ui = NativeUI(self, service)
        ui.login(user)
        removed = []
        for row in self.list_tokens(service, user):
            if row['id'] not in old_ids:
                ui.revoke_token(row['id'])
                removed.append({'name': row['name'], 'id': row['id'], 'id_source': row['id_source']})
        after = self.list_tokens(service, user)
        assert after == before, (self.token_state_summary(before), self.token_state_summary(after))
        # Modern API list.sha1 is a stored digest, not an authentication value.
        # Callers must check actual CREATE credentials before/after this operation.
        self.records['proofs'].append({'kind': 'native-token-id-state-restoration', 'service': service,
                                      'user': user, 'removed': removed, 'restored': self.token_state_summary(after),
                                      'credential_authentication': 'Not performed by UI/state helper'})

    def save(self, name):
        (self.artifacts/name).write_text(json.dumps(self.records, indent=2)+'\n')


class NativeUI:
    def __init__(self, native, service):
        self.native = native
        self.service = service
        self.jar = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(self.jar), NoRedirect())

    def request(self, route, data=None):
        request = urllib.request.Request(self.native.origin(self.service)+route,
                                         data=urllib.parse.urlencode(data).encode() if data is not None else None)
        try:
            response = self.opener.open(request, timeout=10)
        except urllib.error.HTTPError as error:
            response = error
        body = response.read()
        self.native.record('http', {'service': self.service, 'kind': 'native-ui', 'url': request.full_url,
                                   'method': request.get_method(), 'request': data, 'status': response.status,
                                   'headers': dict(response.headers), 'body_base64': base64.b64encode(body).decode(),
                                   'cookie_paths': [(cookie.name, cookie.path) for cookie in self.jar]})
        text = body.decode('utf-8')
        return response.status, text, Fields(text)

    def login(self, user):
        status, _body, fields = self.request('/user/login')
        assert status == 200, status
        status, _body, _fields = self.request('/user/login', {'_csrf': fields.value('_csrf'), 'user_name': user,
                                                            'password': self.native.accounts[user]['password']})
        assert status == 302, status
        status, _body, fields = self.request('/user/settings')
        assert status == 200 and fields.value('name') == user, (status, fields.inputs)
        self.user = user

    def account_state(self, user_id):
        status, _body, fields = self.request('/admin/users/'+str(user_id))
        assert status == 200, status
        result = {name: fields.value(name) for name in ['login_type', 'login_name', 'full_name', 'email', 'website', 'location']}
        result['max_repo_creation'] = int(fields.value('max_repo_creation'))
        for field in fields.inputs:
            if field.get('name') in ['active', 'prohibit_login', 'admin', 'allow_git_hook', 'allow_import_local']:
                result[field['name']] = 'checked' in field
        assert re.fullmatch(r'\d+-\d+', result['login_type']), result
        return result

    def create_repo(self, name):
        status, _body, fields = self.request('/repo/create')
        assert status == 200, status
        uid = fields.value('user_id')
        status, identity = self.native.request(self.service, '/api/v1/user', user=self.user)
        assert status == 200 and str(identity['id']) == uid, (status, identity, uid)
        assert self.request('/repo/create', {'_csrf': fields.value('_csrf'), 'user_id': uid, 'repo_name': name,
                                            'private': 'on', 'readme': 'Default', 'auto_init': 'on'})[0] == 302

    def delete_repo(self, owner, name):
        route = '/'+owner+'/'+name+'/settings'
        status, _body, fields = self.request(route)
        assert status == 200, status
        assert self.request(route, {'_csrf': fields.value('_csrf'), 'action': 'delete', 'repo_name': name})[0] == 302

    def set_rebase(self, owner, name, enabled):
        route = '/'+owner+'/'+name+'/settings'
        status, _body, fields = self.request(route)
        assert status == 200, status
        data = {'_csrf': fields.value('_csrf'), 'action': 'advanced', 'enable_pulls': 'on'}
        if enabled:
            data['pulls_allow_rebase'] = 'on'
        assert self.request(route, data)[0] == 302

    def create_pr(self, owner, name, base, head):
        route = '/'+owner+'/'+name+'/compare/'+urllib.parse.quote(base, safe='')+'...'+urllib.parse.quote(head, safe='')
        status, _body, fields = self.request(route)
        assert status == 200, status
        status, _body, _fields = self.request(route, {'_csrf': fields.value('_csrf'), 'title': 'Native rebase proof',
                                                     'content': '', 'assignee_id': 0, 'milestone_id': 0})
        assert status in (302, 303), status
        status, rows = self.native.request(self.service, '/api/v1/repos/'+owner+'/'+name+'/pulls?state=open', user=owner)
        assert status == 200 and len(rows) == 1, (status, rows)
        return rows[0]['number']

    def merge(self, owner, name, number):
        route = '/'+owner+'/'+name+'/pulls/'+str(number)
        status, _body, fields = self.request(route)
        assert status == 200, status
        return self.request(route+'/merge?merge_style=rebase_before_merging', {'_csrf': fields.value('_csrf'), 'commit_description': ''})[0]

    def revoke_token(self, token_id):
        status, _body, fields = self.request('/user/settings/applications')
        assert status == 200, status
        status, body, _fields = self.request('/user/settings/applications/delete', {'_csrf': fields.value('_csrf'), 'id': token_id})
        assert status == 200 and isinstance(json.loads(body), dict), (status, body)
