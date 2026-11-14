from pathlib import Path
import json
import os
import signal
import subprocess
import time

root = Path('/tmp/heartbleed-lab')
root.mkdir(mode=0o700)
Path('/tmp/heartbleed-home').mkdir(mode=0o700)
config = '/opt/openssl/1.0.1g/ssl/openssl.cnf'
with (root / 'certgen.log').open('w') as output:
    subprocess.run(['/opt/openssl/1.0.1g/bin/openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '2', '-subj', '/CN=heartbleed.invalid', '-keyout', str(root / 'key.pem'), '-out', str(root / 'cert.pem'), '-config', config], check=True, stdout=output, stderr=subprocess.STDOUT)
with (root / 'ec-certgen.log').open('w') as output:
    subprocess.run(['/opt/openssl/1.0.1g/bin/openssl', 'ecparam', '-name', 'prime256v1', '-genkey', '-out', str(root / 'ec-key.pem')], check=True, stdout=output, stderr=subprocess.STDOUT)
    subprocess.run(['/opt/openssl/1.0.1g/bin/openssl', 'req', '-new', '-x509', '-key', str(root / 'ec-key.pem'), '-days', '2', '-subj', '/CN=heartbleed-ec.invalid', '-out', str(root / 'ec-cert.pem'), '-config', config], check=True, stdout=output, stderr=subprocess.STDOUT)
roles = [('affected-doc', '1.0.1d', 10000), ('affected-last', '1.0.1f', 10100), ('fixed', '1.0.1g', 10200), ('disabled', '1.0.1f-no-heartbeats', 10300), ('conditioned-doc', '1.0.1d', 11000), ('conditioned-last', '1.0.1f', 11100), ('conditioned-fixed', '1.0.1g', 11200), ('conditioned-disabled', '1.0.1f-no-heartbeats', 11300)]
children = []
stop = False


def terminate(_signum, _frame):
    global stop
    stop = True


signal.signal(signal.SIGTERM, terminate)
signal.signal(signal.SIGINT, terminate)
try:
    for name, version, port in roles:
        output = (root / (name + '.log')).open('w')
        command = ['/opt/openssl/' + version + '/bin/openssl', 's_server', '-accept', str(port), '-cert', str(root / 'cert.pem'), '-key', str(root / 'key.pem'), '-www', '-quiet']
        if name.startswith('conditioned-'):
            command = ['/opt/openssl/' + version + '/bin/conditioned_server', str(port), str(root / 'cert.pem'), str(root / 'key.pem')]
        child = subprocess.Popen(command, stdout=output, stderr=subprocess.STDOUT, start_new_session=True)
        children.append((name, child, output))
    (root / 'providers.json').write_text(json.dumps({name: {'pid': child.pid, 'version': version, 'port': port, 'kind': 'conditioned' if name.startswith('conditioned-') else 'ordinary'} for (name, child, output), (_, version, port) in zip(children, roles)}, indent=2) + '\n')
    extras = [
        ('ecdsa', ['/opt/openssl/1.0.1f/bin/openssl', 's_server', '-accept', '12000', '-cert', str(root / 'ec-cert.pem'), '-key', str(root / 'ec-key.pem'), '-www', '-quiet']),
        ('upgrades', ['python3', '/opt/heartbleed-lab/starttls.py']),
        ('unrelated-http', ['python3', '-m', 'http.server', '2525', '--bind', '0.0.0.0', '--directory', str(root / 'http')])
    ]
    (root / 'http').mkdir()
    (root / 'http/index.html').write_text('Heartbleed unrelated HTTP control\n')
    for name, command in extras:
        output = (root / (name + '.log')).open('w')
        child = subprocess.Popen(command, stdout=output, stderr=subprocess.STDOUT, start_new_session=True)
        children.append((name, child, output))
    (root / 'service-processes.json').write_text(json.dumps({name: child.pid for name, child, output in children}) + '\n')
    while not stop:
        for name, child, output in children:
            if child.poll() is not None:
                raise RuntimeError(name + ' exited ' + str(child.returncode))
        time.sleep(0.2)
finally:
    for name, child, output in children:
        if child.poll() is None:
            os.killpg(child.pid, signal.SIGTERM)
        try:
            child.wait(timeout=4)
        except subprocess.TimeoutExpired:
            os.killpg(child.pid, signal.SIGKILL)
            child.wait()
        output.close()
