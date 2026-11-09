"""Provision native Ansible configuration and disposable SSH credentials."""
import os
from pathlib import Path
import pwd
import shutil
import subprocess


subprocess.run(['useradd', '--create-home', '--shell', '/bin/bash', 'labuser'], check=True)
identity = pwd.getpwnam('labuser')
directory = Path('/etc/ansible')
directory.mkdir(exist_ok=True)
key = Path('/opt/ansible-fixture-keys/id_ed25519')
subprocess.run(['ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', str(key)], check=True)
public = key.with_suffix('.pub')
public.chmod(0o644)
shared = directory / 'id_ed25519'
shutil.copyfile(key, shared)
os.chown(shared, identity.pw_uid, identity.pw_gid)
shared.chmod(0o600)
protected = directory / 'root_only_key'
shutil.copyfile(key, protected)
protected.chmod(0o600)

inventory = '''[reachable]
module_node ansible_host=node ansible_connection=ssh ansible_user=root ansible_python_interpreter=/usr/bin/python3

[rejected]
module_denied ansible_host=node ansible_connection=ssh ansible_user=denieduser ansible_python_interpreter=/usr/bin/python3
'''
(directory / 'hosts').write_text(inventory)
config = '''[defaults]
inventory = /etc/ansible/hosts
private_key_file = /etc/ansible/id_ed25519
host_key_checking = False
retry_files_enabled = False
timeout = 3
forks = 2
interpreter_python = /usr/bin/python3
[ssh_connection]
ssh_args = -o ControlMaster=no -o ConnectionAttempts=1 -o UserKnownHostsFile=/dev/null
'''
(directory / 'ansible.cfg').write_text(config)
(directory / 'compact.cfg').write_text(config.replace('private_key_file = ', 'private_key_file='))
(directory / 'protected.cfg').write_text(config.replace('/etc/ansible/id_ed25519', '/etc/ansible/root_only_key'))
for path in (Path('/opt/ansible-local'), Path('/opt/ansible-remote')):
    path.mkdir()
    path.chmod(0o777)
os.execvp('python3', ['python3', '-m', 'http.server', '8080', '--bind', '0.0.0.0', '--directory', '/opt/health'])
