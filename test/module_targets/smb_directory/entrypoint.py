"""Provision only public artificial Samba accounts and start the genuine daemon."""
import json
import os
from pathlib import Path
import subprocess

credentials = json.loads(Path('/opt/module-target-credentials.json').read_text())
for user, password in credentials.items():
    subprocess.run(['smbpasswd', '-s', '-a', user], input=(password + '\n' + password + '\n').encode(), check=True)
    subprocess.run(['smbpasswd', '-e', user], check=True)
subprocess.run(['net', 'groupmap', 'add', 'sid=S-1-5-32-544', 'unixgroup=directory_admins', 'type=builtin'], check=True)
os.execvp('smbd', ['smbd', '--foreground', '--no-process-group', '--debug-stdout'])
