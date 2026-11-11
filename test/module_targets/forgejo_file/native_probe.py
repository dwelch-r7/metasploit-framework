"""Independent real Forgejo API, filesystem and reporting-database controls."""
import base64
import configparser
import hashlib
from html.parser import HTMLParser
import http.client
import json
from pathlib import Path
import subprocess
import sys

runtime = json.loads(Path(sys.argv[1]).read_text())
version, phase = sys.argv[2:4]
profile = json.loads((Path(__file__).parent / 'profiles.json').read_text())[version]
user, password = 'module-user', 'module-target-forgejo-password'
public_repo, private_repo = user + '/public-test', user + '/private-test'
requests, commands = [], []
result = {'status': 'starting', 'version': version, 'phase': phase, 'requests': requests, 'commands': commands}


class CodeText(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.stack, self.blocks, self.current = [], [], None

    def handle_starttag(self, tag, attrs):
        if tag == 'code' and self.stack and self.stack[-1] == 'pre':
            self.current = []
        if tag not in {'br', 'hr', 'img', 'input', 'meta', 'link'}:
            self.stack.append(tag)

    def handle_endtag(self, tag):
        if tag == 'code' and self.current is not None:
            self.blocks.append(''.join(self.current))
            self.current = None
        if tag in self.stack:
            self.stack = self.stack[:len(self.stack) - 1 - self.stack[::-1].index(tag)]

    def handle_data(self, data):
        if self.current is not None:
            self.current.append(data)


def execute(service, *argv, expected=0, git=False, owner=False):
    args = runtime['compose'] + ['exec', '-T']
    if git:
        args += ['--user', 'git']
    if owner:
        command = runtime['console_command']
        args += ['--user', command[command.index('--user') + 1]]
    process = subprocess.run(args + [service, *argv], capture_output=True, timeout=45)
    row = {'service': service, 'argv': argv, 'git': git, 'owner': owner, 'exit': process.returncode,
           'stdout_base64': base64.b64encode(process.stdout).decode(), 'stderr_base64': base64.b64encode(process.stderr).decode()}
    commands.append(row)
    assert process.returncode == expected, row
    return process.stdout


def request(method, path, data=None, auth='valid'):
    endpoint = runtime['endpoints']['target']
    connection = http.client.HTTPConnection(endpoint['host'], endpoint['port'], timeout=20)
    headers = {}
    if auth != 'none':
        secret = password if auth == 'valid' else 'module-target-rejected-password'
        headers['Authorization'] = 'Basic ' + base64.b64encode((user + ':' + secret).encode()).decode()
    if data is not None:
        data = json.dumps(data)
        headers['Content-Type'] = 'application/json'
    try:
        connection.request(method, path, data, headers)
        response = connection.getresponse()
        body = response.read()
        requests.append({'method': method, 'path': path, 'auth': auth, 'status': response.status,
                         'headers': response.getheaders(), 'body_base64': base64.b64encode(body).decode()})
        return response.status, body
    finally:
        connection.close()


def api(method, path, data=None, expected=200):
    status, body = request(method, '/api/v1/' + path, data)
    assert status == expected, requests[-1]
    return json.loads(body) if body else None


def markup(text, context=public_repo, auth='valid'):
    status, body = request('POST', '/api/v1/markup', {
        'Mode': 'file', 'Text': text, 'FilePath': 'include.org', 'Context': context
    }, auth=auth)
    parser = CodeText()
    parser.feed(body.decode())
    assert len(parser.blocks) <= 1, requests[-1]
    return {'status': status, 'body_base64': base64.b64encode(body).decode(),
            'text': parser.blocks[0] if parser.blocks else None}


def included(path, context=public_repo, auth='valid'):
    return markup('#+INCLUDE: "' + path + '" src text', context, auth)


def resources(service):
    text = execute(service, 'sh', '-c', 'cat /sys/fs/cgroup/memory.peak /sys/fs/cgroup/memory.events /sys/fs/cgroup/pids.peak /sys/fs/cgroup/pids.events').decode()
    assert 'oom 0' in text and 'oom_kill 0' in text
    assert all(line == 'max 0' for line in text.splitlines() if line.startswith('max ')), text
    return text


try:
    status, body = request('GET', '/api/v1/version', auth='none')
    assert status == 200
    server_version = json.loads(body)['version']
    assert server_version.split('+')[0] == version, server_version
    assert 'forgejo version ' + version + '+' in execute('target', 'forgejo', '--version', git=True).decode()
    binary_sha256 = execute('target', 'sha256sum', '/app/gitea/gitea').decode().split()[0]
    if profile['packaging'] == 'release_binary':
        assert binary_sha256 == profile['sha256']
    status, body = request('GET', '/api/v1/user')
    if status == 401 and phase == 'before':
        execute('target', 'forgejo', 'admin', 'user', 'create', '--username', user, '--password', password,
                '--email', 'module-user@example.invalid', '--must-change-password=false', git=True)
        status, body = request('GET', '/api/v1/user')
    assert status == 200, requests[-1]
    account = json.loads(body)
    assert account['login'] == user and account['is_admin'] is False
    assert request('GET', '/api/v1/user', auth='none')[0] == 401
    assert request('GET', '/api/v1/user', auth='wrong')[0] == 401
    for name, private in [('public-test', False), ('private-test', True)]:
        status, body = request('GET', '/api/v1/repos/' + user + '/' + name)
        if status == 404 and phase == 'before':
            api('POST', 'user/repos', {'name': name, 'private': private, 'auto_init': True}, expected=201)
        else:
            assert status == 200, requests[-1]
        repository = api('GET', 'repos/' + user + '/' + name)
        assert repository['private'] is private and repository['full_name'] == user + '/' + name
    assert request('GET', '/api/v1/repos/' + private_repo, auth='none')[0] == 404
    repositories = api('GET', 'user/repos')
    assert len(repositories) == 2
    repo_state = sorted([{key: repo[key] for key in ['id', 'name', 'full_name', 'private', 'default_branch']} for repo in repositories], key=lambda row: row['name'])
    search = api('GET', 'repos/search?limit=1')
    assert len(search['data']) == 1 and search['data'][0]['full_name'] in [public_repo, private_repo]
    search_first = search['data'][0]['full_name']
    ordinary = markup('#+begin_src text\nNative ordinary Forgejo markup & <tag>\n#+end_src')
    assert ordinary['status'] == 200 and ordinary['text'] == 'Native ordinary Forgejo markup & <tag>', ordinary
    assert included('/etc/passwd', auth='none')['status'] == 401
    assert included('/etc/passwd', auth='wrong')['status'] == 401
    files = {}
    paths = {'default': '/etc/passwd'}
    paths.update({path.stem.replace(' ', '_').replace('-', '_'): '/opt/module-target-files/' + path.name
                  for path in (Path(__file__).parent / 'files').iterdir() if path.is_file()})
    for kind, path in paths.items():
        raw = execute('target', 'cat', path, git=True)
        if kind != 'default':
            assert raw == (Path(__file__).parent / 'files' / Path(path).name).read_bytes()
        document = included(path)
        assert document['status'] == 200
        if profile['vulnerable'] and kind not in ['empty', 'whitespace']:
            assert document['text'] is not None and document['text'].strip(), (kind, document)
            # Real captures show org-mode removes one final line delimiter;
            # files without that delimiter retain their text unchanged.
            assert document['text'].encode() == raw.removesuffix(b'\n'), (kind, document, raw)
            document['raw_bytes_equal'] = document['text'].encode() == raw
        else:
            assert not (document['text'] or '').strip(), (kind, document)
        files[kind] = {'path': path, 'base64': base64.b64encode(raw).decode(),
                       'sha256': hashlib.sha256(raw).hexdigest(), 'rendered': document}
    assert len(base64.b64decode(files['large']['base64'])) > 32768
    negative = {}
    execute('target', 'test', '!', '-e', '/opt/module-target-files/missing-task.txt')
    assert execute('target', 'stat', '-c', '%F', '/opt/module-target-files').strip() == b'directory'
    execute('target', 'cat', '/etc/shadow', git=True, expected=1)
    assert b'Permission denied' in base64.b64decode(commands[-1]['stderr_base64'])
    for label, path in [('missing', '/opt/module-target-files/missing-task.txt'), ('directory', '/opt/module-target-files'), ('unreadable', '/etc/shadow')]:
        document = included(path)
        assert document['status'] == 200 and not (document['text'] or '').strip(), document
        negative[label] = document
    contexts = {name: included('/etc/passwd', context=name) for name in [private_repo, '']}
    assert contexts[private_repo]['status'] == 200
    assert contexts[private_repo]['text'] == files['default']['rendered']['text']
    process = execute('target', 'sh', '-c', 'for name in /proc/[0-9]*/comm; do if test "$(cat "$name" 2>/dev/null)" = gitea; then cat "${name%/comm}/stat"; fi; done').decode().splitlines()
    assert len(process) == 1, process
    fields = process[0].split()
    identity = {'pid': fields[0], 'starttime': fields[21]}
    configuration = execute('target', 'cat', '/data/gitea/conf/app.ini')
    parser = configparser.ConfigParser(interpolation=None)
    parser.read_string('[DEFAULT]\n' + configuration.decode())
    assert parser['database']['DB_TYPE'] == 'sqlite3'
    assert parser.getboolean('security', 'INSTALL_LOCK') and parser.getboolean('server', 'DISABLE_SSH')
    assert parser.getboolean('service', 'DISABLE_REGISTRATION')
    database = execute('reporting_db', 'psql', '-U', 'module_framework', '-d', 'module_targets', '-Atc', 'SELECT current_user,current_database(),version()').decode()
    assert 'module_framework|module_targets|PostgreSQL 16.' in database
    execute('reporting_db', 'env', 'PGPASSWORD=module-target-rejected-password', 'psql', '-h', '127.0.0.1', '-U', 'module_framework', '-d', 'module_targets', '-Atc', 'SELECT current_user', expected=2)
    assert b'password authentication failed' in base64.b64decode(commands[-1]['stderr_base64'])
    console = runtime['console_command']
    owner = console[console.index('--user') + 1]
    host = runtime['module_endpoints']['target']['host']
    code = "require 'socket'; begin; Socket.tcp(ARGV[0],1,connect_timeout:2).close; abort 'Unexpected open port'; rescue Errno::ECONNREFUSED; puts Process.uid.to_s+':'+Process.gid.to_s; end"
    assert execute('framework', 'ruby', '-e', code, host, owner=True).decode().strip() == owner
    result.update(status='native_passed', server_version=server_version, binary_sha256=binary_sha256,
                  files=files, negative=negative, ordinary_markup=ordinary, contexts=contexts,
                  repositories=repo_state, search_first=search_first, account={'id': account['id'], 'login': user, 'is_admin': False},
                  identity=identity, configuration_sha256=hashlib.sha256(configuration).hexdigest(),
                  cgroups={service: resources(service) for service in ['target', 'reporting_db']}, database=database,
                  refused_port={'host': host, 'port': 1, 'owner': owner})
finally:
    Path(runtime['artifacts'], 'native-' + phase + '.json').write_text(json.dumps(result, indent=2) + '\n')
print(json.dumps({'phase': phase, 'status': result['status'], 'requests': len(requests)}))
