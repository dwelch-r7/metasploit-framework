"""Create artificial account data through native Linux account tools."""
import crypt
import os
from pathlib import Path
import pwd
import subprocess


subprocess.run(['useradd', '--create-home', '--shell', '/bin/bash', 'labuser'], check=True)
subprocess.run(['useradd', '--create-home', '--home-dir', '/home/history user',
                '--shell', '/bin/bash', 'historyuser'], check=True)
subprocess.run(['useradd', '--no-create-home', '--shell', '/usr/sbin/nologin',
                'lockeduser'], check=True)
# chpasswd generates the real shadow records; no parser-produced hash is seeded.
subprocess.run(['chpasswd', '--crypt-method', 'SHA512'],
               input=b'root:module-target-root-password\nlabuser:module-target-user-password\n'
                     b'historyuser:module-target-history-password\n', check=True)

histories = {
    '.ash_history': 'printf "ash history %s\\n" fixture\n',
    '.bash_history': 'printf "module-target bash history\\n"\nprintf "Unicode caf\u00e9 and <&>\\n"\n',
    '.mysql_history': 'select current_user();\nselect 41 + 1;\n',
    '.psql_history': 'select current_user;\nselect 42;\n',
    '.dbshell': 'db.version()\ndb.getName()\n',
    '.viminfo': '# This viminfo file was written by Vim\n\'0  1  0  /tmp/module-target-note\n',
    '.zsh_history': ''
}
for username in ('root', 'labuser', 'historyuser'):
    account = pwd.getpwnam(username)
    home = Path(account.pw_dir)
    home.chmod(0o700)
    for filename, content in histories.items():
        path = home / filename
        path.write_text(content.replace('fixture', username), encoding='utf-8')
        path.chmod(0o600)
        os.chown(path, account.pw_uid, account.pw_gid)

Path('/etc/sudoers').write_text('# Public module-target collection fixture\nroot ALL=(ALL:ALL) ALL\n')
Path('/etc/sudoers').chmod(0o440)
Path('/var/log/wtmp').touch()
Path('/var/log/lastlog').touch()
old_hash = crypt.crypt('module-target-old-password', '$6$historyfixture$')
Path('/etc/security/opasswd').write_text(f'labuser:1000:1:{old_hash}\n')
Path('/etc/security/opasswd').chmod(0o600)
