"""Independent process/cwd facts; no payload or Framework methods are replaced."""
from pathlib import Path
import base64
import hashlib
import json
import os
import subprocess
import sys

action, argument = sys.argv[1:]
if action == 'session-cwd':
    pid = int(argument)
    assert pid > 1
    process = Path('/proc', str(pid))
    status = dict(line.split(':', 1) for line in (process / 'status').read_text().splitlines())
    uid, gid = int(status['Uid'].split()[1]), int(status['Gid'].split()[1])
    # Match the observed process credentials for protected /proc link reads;
    # the disposable target needs no extra ptrace capability for this observer.
    os.setgroups([])
    os.setgid(gid)
    os.setuid(uid)
    cwd = os.readlink(process / 'cwd')
    executable = os.readlink(process / 'exe')
    image = (process / 'exe').read_bytes()
    result = dict(pid=pid, uid=uid, observer_uid=os.geteuid(), cwd=cwd,
                  cwd_exists=(process / 'cwd').exists(), cwd_deleted=cwd.endswith(' (deleted)'),
                  executable=executable, executable_deleted=executable.endswith(' (deleted)'),
                  executable_uid=(process / 'exe').stat().st_uid,
                  executable_sha256=hashlib.sha256(image).hexdigest(), executable_base64=base64.b64encode(image).decode())
elif action in ['command', 'command-in-writable']:
    log = Path('/tmp/module-target-sudo-native-callback-log')
    assert not log.exists()
    # A background session inherits its parent's output. A regular owned log
    # avoids waiting on that live child's inherited pipe in communicate().
    with log.open('xb') as handle:
        os.chown(log, 1001, 1001)
        command = base64.b64decode(argument).decode()
        environment = dict(os.environ, HOME='/home/lab', USER='lab', LOGNAME='lab', SHELL='/bin/bash',
                           PATH='/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin')
        launched = subprocess.run(['/bin/sh', '-c', command], user=1001, group=1001, extra_groups=[],
                                  cwd='/tmp' if action == 'command-in-writable' else '/home/lab', env=environment, stdin=subprocess.DEVNULL,
                                  stdout=handle, stderr=subprocess.STDOUT, timeout=10)
    result = dict(exit=launched.returncode, output_path=str(log))
else:
    raise ValueError(action)
print(json.dumps(result))
