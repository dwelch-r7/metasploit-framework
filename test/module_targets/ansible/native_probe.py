"""Exercise real Ansible/OpenSSH clients independently of Framework."""
import base64
import json
import os
from pathlib import Path
import pwd
import subprocess


commands = []


def command(argv, *, expected=0, env=None):
    process = subprocess.run(argv, capture_output=True, env=env, timeout=45)
    commands.append(dict(argv=argv, exitstatus=process.returncode,
                         stdout=process.stdout.decode(), stderr=process.stderr.decode()))
    assert process.returncode == expected, commands[-1]
    return process.stdout.decode()


identity = pwd.getpwuid(os.getuid())
assert identity.pw_name in ('root', 'labuser')
version = command(['/usr/bin/ansible', '--version'])
assert 'ansible [core 2.12.0]' in version
inventory = json.loads(command(['/usr/bin/ansible-inventory', '--list']))
hosts = inventory['_meta']['hostvars']
assert set(hosts) == {'module_node', 'module_denied'}
assert hosts['module_node']['ansible_user'] == 'root'
assert hosts['module_denied']['ansible_user'] == 'denieduser'
ping = command(['/usr/bin/ansible', 'reachable', '-m', 'ping', '-o'])
assert 'module_node | SUCCESS =>' in ping and '"ping": "pong"' in ping
refused = command(['/usr/bin/ansible', 'rejected', '-m', 'ping', '-o'], expected=4)
assert refused.startswith('module_denied | UNREACHABLE!') and 'Permission denied' in refused
all_hosts = command(['/usr/bin/ansible', 'all', '-m', 'ping', '-o'], expected=4)
assert 'module_node | SUCCESS =>' in all_hosts and 'module_denied | UNREACHABLE!' in all_hosts
ssh = ['/usr/bin/ssh', '-i', '/etc/ansible/id_ed25519', '-o', 'BatchMode=yes',
       '-o', 'StrictHostKeyChecking=no', '-o', 'UserKnownHostsFile=/dev/null',
       '-o', 'ConnectTimeout=3']
assert command(ssh + ['root@node', 'id -un']).strip() == 'root'
command(ssh + ['denieduser@node', 'id -un'], expected=255)
files = {}
for path in ('/etc/ansible/ansible.cfg', '/etc/ansible/compact.cfg', '/etc/ansible/protected.cfg',
             '/etc/ansible/id_ed25519', '/etc/ansible/root_only_key'):
    try:
        files[path] = dict(state='readable', data=base64.b64encode(Path(path).read_bytes()).decode())
    except PermissionError:
        files[path] = dict(state='denied')
assert files['/etc/ansible/id_ed25519']['state'] == 'readable'
assert files['/etc/ansible/root_only_key']['state'] == ('readable' if identity.pw_name == 'root' else 'denied')
environment = os.environ.copy()
environment['ANSIBLE_CONFIG'] = '/etc/ansible/compact.cfg'
compact = command(['/usr/bin/ansible-config', 'dump', '--only-changed'], env=environment)
assert 'DEFAULT_PRIVATE_KEY_FILE' in compact and '/etc/ansible/id_ed25519' in compact
Path('/tmp/module-target-native-command.sh').write_text('#!/bin/sh\nprintf "module-target-native-deployment\\n"\n')
try:
    for _ in range(2):
        play = command(['/usr/bin/ansible-playbook', '/opt/native-playbook.yaml'])
        assert 'failed=0' in play and 'unreachable=0' in play
        assert command(ssh + ['root@node', 'test ! -e /opt/ansible-remote/native-command.sh']) == ''
finally:
    Path('/tmp/module-target-native-command.sh').unlink()
print(json.dumps(dict(username=identity.pw_name, uid=identity.pw_uid, version=version,
                     inventory=inventory, ping=ping, refused=refused, all_hosts=all_hosts, files=files,
                     commands=commands)))
