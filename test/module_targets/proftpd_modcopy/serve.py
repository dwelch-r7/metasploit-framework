"""Run the real FTP and PHP services inside the single disposable target."""
from pathlib import Path
import os
import signal
import subprocess
import time

Path('/tmp/copy').mkdir(mode=0o777)
os.chown('/tmp/copy', 33, 33)
os.chmod('/tmp/copy', 0o777)
configuration = Path('/opt/module-target-proftpd/proftpd.conf').read_text()
if os.environ.get('COPY_ENGINE') == 'off':
    configuration += '\nCopyEngine off\n'
Path('/run/proftpd.conf').write_text(configuration)
children = []
logs = []
stopping = False

def stop(number, frame):
    global stopping
    stopping = True

signal.signal(signal.SIGTERM, stop)
signal.signal(signal.SIGINT, stop)
try:
    for name, argv, user in [
        ('ftp', ['/usr/local/sbin/proftpd', '-n', '-c', '/run/proftpd.conf'], 0),
        ('php', ['php', '-d', 'disable_functions=', '-S', '0.0.0.0:8080', '-t', '/var/www/html'], 33),
    ]:
        log = Path('/run', name + '-output.log').open('ab')
        logs.append(log)
        children.append(subprocess.Popen(argv, user=user, group=user, extra_groups=[],
                                         stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT))
    while not stopping and all(child.poll() is None for child in children):
        time.sleep(0.2)
finally:
    for child in children:
        if child.poll() is None:
            child.terminate()
    for child in children:
        try:
            child.wait(timeout=5)
        except subprocess.TimeoutExpired:
            child.kill()
            child.wait()
    for log in logs:
        log.close()
assert stopping, 'A required native service exited unexpectedly'
