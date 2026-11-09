"""Read actual account data and enforce native permission controls."""
import base64
import crypt
import json
import os
import platform
from pathlib import Path
import pwd
import subprocess


def encoded(content):
    return base64.b64encode(content).decode('ascii')


def read(path):
    try:
        return dict(state='readable', data=encoded(Path(path).read_bytes()))
    except FileNotFoundError:
        return dict(state='missing')
    except PermissionError:
        return dict(state='denied')


identity = pwd.getpwuid(os.getuid())
assert identity.pw_name in ('root', 'labuser')
release = Path('/etc/os-release').read_text()
assert 'ID=ubuntu' in release and 'VERSION_ID="22.04"' in release
accounts = {account.pw_name: account.pw_dir for account in pwd.getpwall()}
assert accounts['historyuser'] == '/home/history user'
names = ('.ash_history', '.bash_history', '.csh_history', '.ksh_history',
         '.sh_history', '.tcsh_history', '.zsh_history', '.mysql_history',
         '.psql_history', '.dbshell', '.viminfo')
histories = {username: {name: read(str(Path(home) / name)) for name in names}
             for username, home in accounts.items()}
files = {path: read(path) for path in ('/etc/passwd', '/etc/shadow',
                                      '/etc/security/opasswd', '/etc/sudoers')}
assert files['/etc/passwd']['state'] == 'readable'
assert histories['labuser']['.bash_history']['state'] == 'readable'
assert histories['labuser']['.zsh_history'] == dict(state='readable', data='')
assert histories['labuser']['.csh_history']['state'] == 'missing'
if identity.pw_name == 'root':
    assert all(record['state'] == 'readable' for record in files.values())
    assert histories['root']['.bash_history']['state'] == 'readable'
    shadow = {line.split(':')[0]: line.split(':')[1]
              for line in Path('/etc/shadow').read_text().splitlines()}
    for username, password in (('root', 'module-target-root-password'),
                               ('labuser', 'module-target-user-password'),
                               ('historyuser', 'module-target-history-password')):
        assert shadow[username].startswith('$6$')
        assert crypt.crypt(password, shadow[username]) == shadow[username]
    assert shadow['lockeduser'].startswith('!')
else:
    assert all(files[path]['state'] == 'denied'
               for path in ('/etc/shadow', '/etc/security/opasswd', '/etc/sudoers'))
    assert histories['root']['.bash_history']['state'] == 'denied'
    assert histories['historyuser']['.bash_history']['state'] == 'denied'
logs = subprocess.run(['/bin/sh', '-c', '/usr/bin/last && /usr/bin/lastlog'],
                      capture_output=True, check=True)
assert not logs.stderr
print(json.dumps(dict(username=identity.pw_name, uid=identity.pw_uid,
                     release=release, python=platform.python_version(),
                     hostname=subprocess.check_output(['hostname']).decode().strip(),
                     accounts=accounts, histories=histories, files=files,
                     logs=encoded(logs.stdout))))
