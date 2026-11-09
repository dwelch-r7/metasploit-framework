"""Create public account fixtures with native account, OpenSSH and RubyGems tools."""
import json
import os
from pathlib import Path
import pwd
import re
import subprocess


records = []


def run(arguments, **options):
    result = subprocess.run(arguments, capture_output=True, text=True,
                            **options)
    records.append(dict(argv=arguments, stdout=result.stdout,
                        stderr=result.stderr, exitstatus=result.returncode))
    Path('/opt/credential-state/seed-commands.json').write_text(json.dumps(records, indent=2))
    if result.returncode:
        raise RuntimeError(json.dumps(records[-1]))
    return result.stdout


accounts = {
    'root': '/root', 'labuser': '/home/lab user',
    'emptyuser': '/home/empty-user', 'missinguser': '/home/missing-user',
    'denieduser': '/home/denied-user',
}
for username, home in accounts.items():
    if username != 'root':
        run(['useradd', '--create-home', '--home-dir', home,
             '--shell', '/bin/bash', username])
    Path(home).chmod(0o711 if username != 'root' else 0o700)
run(['chpasswd'], input='root:module-target-root-password\n'
    'labuser:module-target-user-password\n'
    'denieduser:module-target-denied-password\n')

ssh = {}
for username in ('root', 'labuser', 'denieduser'):
    identity = pwd.getpwnam(username)
    directory = Path(identity.pw_dir) / '.ssh'
    directory.mkdir(mode=0o700)
    os.chown(directory, identity.pw_uid, identity.pw_gid)
    private = directory / 'id_rsa'
    run(['runuser', '-u', username, '--', 'ssh-keygen', '-q', '-t', 'rsa',
         '-b', '2048', '-m', 'PEM', '-N', '', '-f', str(private)])
    authorized = directory / 'authorized_keys'
    authorized.write_bytes(Path(str(private) + '.pub').read_bytes())
    authorized.chmod(0o600)
    os.chown(authorized, identity.pw_uid, identity.pw_gid)
    configuration = directory / 'config'
    configuration.write_text('Host module-target-self\n'
                             '  HostName 127.0.0.1\n'
                             f'  User {username}\n'
                             f'  IdentityFile "{private}"\n'
                             '  IdentitiesOnly yes\n')
    configuration.chmod(0o600)
    os.chown(configuration, identity.pw_uid, identity.pw_gid)
    ssh[username] = dict(private=str(private),
                         public_fingerprint=run(['ssh-keygen', '-lf', str(private)]).strip())
empty = Path(accounts['labuser']) / '.ssh/empty'
empty.touch(mode=0o600)
lab = pwd.getpwnam('labuser')
os.chown(empty, lab.pw_uid, lab.pw_gid)
denied = Path(accounts['labuser']) / '.ssh/denied-note'
denied.write_text('Public permission-denied file fixture\n')
denied.chmod(0)
(Path(accounts['emptyuser']) / '.ssh').mkdir(mode=0o755)
empty_gem = Path(accounts['emptyuser']) / '.gem'
empty_gem.mkdir(mode=0o700)
empty_gem_file = empty_gem / 'credentials'
empty_gem_file.touch(mode=0o600)
empty_identity = pwd.getpwnam('emptyuser')
os.chown(empty_gem, empty_identity.pw_uid, empty_identity.pw_gid)
os.chown(empty_gem_file, empty_identity.pw_uid, empty_identity.pw_gid)

Path('/etc/ssh/sshd_config.d/module-target.conf').write_text(
    'PasswordAuthentication no\nPermitRootLogin prohibit-password\n'
    'PubkeyAuthentication yes\nUsePAM yes\n')
registry = {
    'root': dict(username='registry_root', password='module-target-root:docker:password'),
    'labuser': dict(username='registry_user', password='module-target-user:docker:password'),
    'denieduser': dict(username='registry_denied', password='module-target-denied:docker:password'),
}
auth = Path('/opt/registry-auth')
auth.mkdir(exist_ok=True)
for index, credential in enumerate(registry.values()):
    run(['htpasswd', '-Bbc' if index == 0 else '-Bb', str(auth / 'htpasswd'),
         credential['username'], credential['password']])

gemstash = {}
Path('/opt/credential-state/gemstash').mkdir(parents=True, exist_ok=True)
for username in ('root', 'labuser', 'denieduser'):
    output = run(['bundle', 'exec', 'gemstash', 'authorize', '--name', username,
                  '--config-file', '/opt/credential-fixture/gemstash.yml'],
                 cwd='/opt/gemstash')
    match = re.search(r'Your new key is: (\S+)', output)
    assert match, output
    gemstash[username] = match.group(1)
    home = Path(accounts[username])
    if username != 'labuser':
        directory = home / '.gem'
        directory.mkdir(mode=0o700)
        credentials = directory / 'credentials'
        credentials.touch(mode=0o600)
        identity = pwd.getpwnam(username)
        os.chown(directory, identity.pw_uid, identity.pw_gid)
        os.chown(credentials, identity.pw_uid, identity.pw_gid)
    script = ('require "rubygems";require "json";'
              'Gem.configuration.set_api_key(:rubygems_api_key,ARGV[0]);'
              'Gem.configuration.set_api_key("http://127.0.0.1:9292/private",ARGV[0]) if ARGV[1]=="multiple";'
              'puts JSON.generate(path:Gem.configuration.credentials_path,version:Gem::VERSION,'
              'key:Gem.configuration.rubygems_api_key,keys:Gem.configuration.api_keys)')
    run(['runuser', '-u', username, '--', 'ruby', '-e', script,
         gemstash[username], 'multiple' if username == 'root' else 'single'])

state = dict(accounts=accounts, ssh=ssh, registry=registry,
             gemstash=gemstash, commands=records)
Path('/opt/credential-state/seed.json').write_text(json.dumps(state, indent=2))
