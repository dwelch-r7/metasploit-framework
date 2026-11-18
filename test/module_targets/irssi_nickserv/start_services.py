"""Run both genuine services with bounded graceful shutdown; runtime unverified."""
from pathlib import Path
import json
import os
import pwd
import signal
import subprocess
import sys
import time

processes = []
stopping = False


def stop(signum, _frame):
    global stopping
    stopping = True
    for process in reversed(processes):
        if process.poll() is None:
            process.send_signal(signal.SIGTERM)


signal.signal(signal.SIGTERM, stop)
signal.signal(signal.SIGINT, stop)
account = pwd.getpwnam('irc')
commands = [
    (['/usr/sbin/ngircd', '--nodaemon', '--config', '/etc/ngircd/module-target.conf'], {}),
    (['/usr/bin/atheme-services', '-n', '-c', '/etc/atheme/module-target.conf',
      '-l', '/run/module-target-atheme/atheme.log', '-p', '/run/module-target-atheme/atheme.pid',
      '-D', '/var/lib/atheme'], {'user': account.pw_uid, 'group': account.pw_gid, 'extra_groups': []}),
]
status = 1
try:
    for argv, options in commands:
        processes.append(subprocess.Popen(argv, **options))
    Path('/opt/native-artifacts/service-launch.json').write_text(json.dumps([
        {'argv': args, 'pid': process.pid}
        for (args, _options), process in zip(commands, processes)
    ], indent=2) + '\n')
    while not stopping and all(process.poll() is None for process in processes):
        time.sleep(0.2)
    status = 0 if stopping else 1
finally:
    stop(signal.SIGTERM, None)
    deadline = time.monotonic() + 10
    for process in reversed(processes):
        try:
            process.wait(max(0.01, deadline - time.monotonic()))
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(5)
sys.exit(status)
