"""Validate actual credentials, clients, permissions and local authentication."""
import base64
import hashlib
import json
import os
from pathlib import Path
import pwd
import subprocess
import sys
import urllib.error
import urllib.request


def files_for_user():
    accounts = json.loads(Path('/opt/credential-state/seed.json').read_text())['accounts']
    files = {}
    for username, home in accounts.items():
        names = [str(Path(home) / suffix) for suffix in (
            '.docker/config.json', '.gem/credentials', '.local/share/gem/credentials',
            '.ssh/id_rsa', '.ssh/id_rsa.pub', '.ssh/authorized_keys',
            '.ssh/config', '.ssh/empty', '.ssh/denied-note', '.ssh/known_hosts')]
        try:
            names += [str(path) for path in (Path(home) / '.ssh').iterdir()]
        except (PermissionError, FileNotFoundError):
            pass
        files[username] = {}
        for filename in sorted(set(names)):
            try:
                data = Path(filename).read_bytes()
                metadata = Path(filename).stat()
                files[username][filename] = dict(state='readable', data=base64.b64encode(data).decode(),
                                                sha256=hashlib.sha256(data).hexdigest(), uid=metadata.st_uid,
                                                mode=oct(metadata.st_mode & 0o777))
            except FileNotFoundError:
                files[username][filename] = dict(state='missing')
            except PermissionError:
                files[username][filename] = dict(state='denied')
    return dict(username=pwd.getpwuid(os.getuid()).pw_name, uid=os.getuid(), files=files)


if '--inspect' in sys.argv:
    print(json.dumps(files_for_user()))
    sys.exit(0)

seed = json.loads(Path('/opt/credential-state/seed.json').read_text())
evidence = dict(commands=[], requests=[], users={}, seed=seed,
                release=Path('/etc/os-release').read_text())


def run(arguments, expected=0, **options):
    result = subprocess.run(arguments, capture_output=True, timeout=25, **options)
    entry = dict(argv=arguments, stdout_base64=base64.b64encode(result.stdout).decode(),
                 stderr=result.stderr.decode(errors='replace'), exitstatus=result.returncode)
    evidence['commands'].append(entry)
    assert result.returncode == expected, entry
    return result.stdout


def request(url, username, password, expected):
    message = urllib.request.Request(url)
    message.add_header('Authorization', 'Basic ' + base64.b64encode(f'{username}:{password}'.encode()).decode())
    try:
        response = urllib.request.urlopen(message, timeout=5)
    except urllib.error.HTTPError as error:
        response = error
    data = response.read()
    entry = dict(url=url, username=username, status=response.code,
                 headers=dict(response.headers), body_base64=base64.b64encode(data).decode())
    evidence['requests'].append(entry)
    assert response.code == expected, entry
    return data


try:
    assert os.getuid() == 0
    assert 'VERSION_CODENAME=bookworm' in evidence['release']
    evidence['docker_version'] = run(['docker', '--version']).decode().strip()
    ruby = 'require "rubygems";require "json";require "digest";puts JSON.generate(ruby:RUBY_VERSION,rubygems:Gem::VERSION,path:Gem.configuration.credentials_path,key:Gem.configuration.rubygems_api_key,keys:Gem.configuration.api_keys,source_sha256:Digest::SHA256.file(Gem::ConfigFile.instance_method(:load_api_keys).source_location.first).hexdigest)'
    for username in ('root', 'labuser', 'denieduser'):
        output = run(['runuser', '-u', username, '--', 'ruby', '-e', ruby])
        client = json.loads(output)
        assert client['ruby'] == '3.3.13' and client['rubygems'] == '3.5.22', client
        assert client['key'] == seed['gemstash'][username]
        evidence['users'][username] = dict(gem_client=client)
        private = seed['ssh'][username]['private']
        known = str(Path(seed['accounts'][username]) / '.ssh/known_hosts')
        login = ['runuser', '-u', username, '--', 'ssh', '-n', '-i', private,
                 '-o', 'IdentitiesOnly=yes', '-o', 'BatchMode=yes', '-o', 'HashKnownHosts=no',
                 '-o', f'UserKnownHostsFile="{known}"', '-o', 'StrictHostKeyChecking=accept-new',
                 '-o', 'ConnectTimeout=3', f'{username}@127.0.0.1', 'id -un']
        assert run(login).decode().strip() == username
        credential = seed['registry'][username]
        directory = str(Path(seed['accounts'][username]) / '.docker')
        native = ['runuser', '-u', username, '--', 'docker', '--config', directory,
                  'login', '127.0.0.1:5000', '--username', credential['username'], '--password-stdin']
        assert b'Login Succeeded' in run(native, input=(credential['password'] + '\n').encode())
        stored = json.loads((Path(directory) / 'config.json').read_text())
        decoded = base64.b64decode(stored['auths']['127.0.0.1:5000']['auth']).decode()
        assert decoded == credential['username'] + ':' + credential['password']
        request('http://127.0.0.1:5000/v2/', credential['username'], credential['password'], 200)
        request('http://127.0.0.1:5000/v2/', credential['username'], credential['password'].split(':')[0], 401)
    assert evidence['users']['labuser']['gem_client']['path'] == '/home/lab user/.local/share/gem/credentials'
    assert evidence['users']['root']['gem_client']['path'] == '/root/.gem/credentials'
    empty_client = json.loads(run(['runuser', '-u', 'emptyuser', '--', 'ruby', '-e', ruby]))
    assert empty_client['key'] is None and empty_client['keys'] == {}

    for filename in ('/tmp/module-target-unauthorized-key', '/tmp/module-target-unauthorized-key.pub'):
        Path(filename).unlink(missing_ok=True)
    run(['ssh-keygen', '-q', '-t', 'rsa', '-b', '2048', '-m', 'PEM', '-N', '', '-f', '/tmp/module-target-unauthorized-key'])
    refused = run(['ssh', '-n', '-i', '/tmp/module-target-unauthorized-key', '-o', 'IdentitiesOnly=yes',
                   '-o', 'BatchMode=yes', '-o', 'UserKnownHostsFile=/dev/null', '-o', 'StrictHostKeyChecking=no',
                   '-o', 'ConnectTimeout=3', 'root@127.0.0.1', 'id -un'], expected=255)
    credential = seed['registry']['labuser']
    run(['runuser', '-u', 'emptyuser', '--', 'docker', '--config', '/home/empty-user/.docker', 'login',
         '127.0.0.1:5000', '--username', credential['username'], '--password-stdin'], input=(credential['password'] + '\n').encode())
    run(['runuser', '-u', 'emptyuser', '--', 'docker', '--config', '/home/empty-user/.docker', 'logout', '127.0.0.1:5000'])
    assert json.loads(Path('/home/empty-user/.docker/config.json').read_text())['auths'] == {}
    for username in ('denieduser',):
        docker_directory = Path(seed['accounts'][username]) / '.docker'
        docker_directory.chmod(0o755)
        (docker_directory / 'config.json').chmod(0)
        gem_directory = Path(seed['accounts'][username]) / '.gem'
        gem_directory.chmod(0o755)
        (gem_directory / 'credentials').chmod(0)

    # A local package and the actual RubyGems client prove Gemstash authorization.
    package = Path('/opt/credential-state/gem-proof')
    package.mkdir(exist_ok=True)
    (package / 'proof.rb').write_text('MODULE_TARGET_GEM_PROOF = 42\n')
    for index, username in enumerate(('root', 'labuser')):
        version = f'1.0.{index}'
        (package / 'module-target-credential-proof.gemspec').write_text(
            'Gem::Specification.new do |spec|\n'
            f'spec.name="module-target-credential-proof";spec.version="{version}";'
            'spec.authors=["Module Target"];spec.summary="Owned local credential proof";'
            'spec.files=["proof.rb"];spec.license="MIT"\nend\n')
        run(['gem', 'build', 'module-target-credential-proof.gemspec'], cwd=package)
        gem = package / f'module-target-credential-proof-{version}.gem'
        environment = dict(os.environ, RUBYGEMS_HOST='http://127.0.0.1:9292/private')
        environment.pop('GEM_HOST_API_KEY', None)
        run(['runuser', '-u', username, '--', 'gem', 'push', str(gem),
             '--key', 'rubygems', '--host', 'http://127.0.0.1:9292/private'], env=environment)
        url = f'http://127.0.0.1:9292/private/gems/module-target-credential-proof-{version}.gem'
        assert request(url, seed['gemstash'][username], '', 200) == gem.read_bytes()
        request(url, 'module-target-invalid-key', '', 401)
        run(['runuser', '-u', username, '--', 'gem', 'yank', 'module-target-credential-proof',
             '--version', version, '--key', 'rubygems'], env=environment)
    evidence['file_states'] = {'root': files_for_user()}
    output = run(['runuser', '-u', 'labuser', '--', 'python3', __file__, '--inspect'])
    evidence['file_states']['labuser'] = json.loads(output)
    assert evidence['file_states']['labuser']['uid'] == pwd.getpwnam('labuser').pw_uid
    assert evidence['file_states']['labuser']['files']['labuser']['/home/lab user/.ssh/empty']['data'] == ''
    assert evidence['file_states']['labuser']['files']['labuser']['/home/lab user/.ssh/known_hosts']['state'] == 'readable'
    assert evidence['file_states']['labuser']['files']['labuser']['/home/lab user/.ssh/denied-note']['state'] == 'denied'
    for username in ('root', 'labuser'):
        evidence['file_states'][username]['gem_key'] = evidence['users'][username]['gem_client']['key']
finally:
    print(json.dumps(evidence, indent=2))
