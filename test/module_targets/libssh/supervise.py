"""Run source-built SSH servers with real Unix command/shell callbacks."""
from pathlib import Path
import json
import os
import signal
import subprocess
import sys
import time

root = Path('/tmp/libssh-lab')
root.mkdir(mode=0o700)
Path('/tmp/libssh-home').mkdir(mode=0o700)
keys = root / 'keys'
keys.mkdir(mode=0o700)
for kind, options in [('rsa', ['-b', '2048']), ('dsa', []), ('ecdsa', ['-b', '256'])]:
    subprocess.run(['ssh-keygen', '-t', kind, *options, '-m', 'PEM', '-N', '', '-f', str(keys / kind), '-q'], check=True)
profiles = [
    ('affected-08', '0.8.3', 'open', 2222, None),
    ('fixed-08', '0.8.4', 'open', 2223, None),
    ('affected-07', '0.7.5', 'open', 2224, None),
    ('fixed-07', '0.7.6', 'open', 2225, None),
    ('versionless', '0.8.3', 'open', 2226, 'libssh'),
    ('custom-banner', '0.8.3', 'open', 2227, 'NativeSSHService'),
    ('application-guard', '0.8.3', 'guarded', 2228, None)
]
processes = []
logs = []
stop = False


def terminate(_signum, _frame):
    global stop
    stop = True


signal.signal(signal.SIGTERM, terminate)
signal.signal(signal.SIGINT, terminate)
try:
    for name, version, mode, port, banner in profiles:
        argv = ['/opt/libssh/' + version + '/server-' + mode, '--rsakey=' + str(keys / 'rsa'), '--dsakey=' + str(keys / 'dsa'), '--ecdsakey=' + str(keys / 'ecdsa'), '-p', str(port), '0.0.0.0']
        environment = dict(os.environ)
        if banner is not None:
            environment['LIBSSH_LAB_BANNER'] = banner
        log = (root / (name + '.log')).open('w')
        logs.append(log)
        child = subprocess.Popen(argv, env=environment, stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
        processes.append((name, child))
    log = (root / 'smtp.log').open('w')
    logs.append(log)
    processes.append(('smtp', subprocess.Popen(['python3', '-m', 'smtpd', '-n', '-c', 'DebuggingServer', '0.0.0.0:2525'], stdout=log, stderr=subprocess.STDOUT, start_new_session=True)))
    (root / 'pids.json').write_text(json.dumps({name: child.pid for name, child in processes}) + '\n')
    while not stop:
        for name, child in processes:
            if child.poll() is not None:
                raise RuntimeError(name + ' exited: ' + str(child.returncode))
        time.sleep(0.25)
finally:
    for name, child in processes:
        if child.poll() is None:
            os.killpg(child.pid, signal.SIGTERM)
    for name, child in processes:
        try:
            child.wait(timeout=4)
        except subprocess.TimeoutExpired:
            os.killpg(child.pid, signal.SIGKILL)
            child.wait()
    for log in logs:
        log.close()
