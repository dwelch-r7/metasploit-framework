"""Start a real OpenSSH server accepting only the disposable controller key."""
import os
from pathlib import Path
import shutil
import subprocess
import time


subprocess.run(['useradd', '--create-home', '--shell', '/bin/bash', 'denieduser'], check=True)
Path('/run/sshd').mkdir(exist_ok=True)
subprocess.run(['ssh-keygen', '-A'], check=True)
public = Path('/opt/ansible-fixture-keys/id_ed25519.pub')
deadline = time.monotonic() + 60
while not public.exists():
    assert time.monotonic() < deadline, 'Controller public key was not provisioned'
    time.sleep(0.1)
directory = Path('/root/.ssh')
directory.mkdir(mode=0o700)
shutil.copyfile(public, directory / 'authorized_keys')
(directory / 'authorized_keys').chmod(0o600)
Path('/etc/ssh/sshd_config').write_text('''Port 22
HostKey /etc/ssh/ssh_host_ed25519_key
PermitRootLogin prohibit-password
PasswordAuthentication no
KbdInteractiveAuthentication no
UsePAM yes
AllowUsers root
Subsystem sftp internal-sftp
''')
Path('/opt/ansible-remote').mkdir(mode=0o777)
os.execv('/usr/sbin/sshd', ['/usr/sbin/sshd', '-D', '-e'])
