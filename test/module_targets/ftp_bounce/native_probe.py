"""Use genuine FTP active transfers and HTTP/TCP controls before owning calls."""
import ftplib
import hashlib
import json
from pathlib import Path
import socket
import subprocess
import sys
import traceback
import urllib.request

runtime = json.loads(Path(sys.argv[1]).read_text())
endpoints = runtime['module_endpoints']
destination = endpoints['destination']['host']
result = {'status': 'native_failed', 'framework_calls': 0, 'profiles': {}, 'http': {}}


def port_argument(port):
    return ','.join(destination.split('.') + [str(port // 256), str(port % 256)])


def command(client, text):
    try:
        return client.sendcmd(text)
    except (ftplib.error_perm, ftplib.error_temp) as error:
        return str(error)


try:
    result['package'] = subprocess.check_output(['dpkg-query', '-W', '-f=${Version}', 'proftpd-core'], text=True)
    result['version'] = subprocess.check_output(['proftpd', '-v'], text=True).strip()
    result['binary_sha256'] = hashlib.sha256(Path('/usr/sbin/proftpd').read_bytes()).hexdigest()
    result['config'] = Path('/etc/proftpd/target.conf').read_text()
    for port in [80, 8080, 8082]:
        with urllib.request.urlopen(f'http://{destination}:{port}/', timeout=3) as response:
            body = response.read()
            assert response.status == 200 and b'It works!' in body
            result['http'][str(port)] = {'status': response.status, 'body_sha256': hashlib.sha256(body).hexdigest()}
    try:
        with socket.create_connection((destination, 8081), timeout=2):
            raise AssertionError('Expected closed destination port 8081')
    except ConnectionRefusedError:
        result['closed_port'] = 8081
    for relay in ['permissive', 'protected']:
        profiles = {}
        for name, username, password in [('anonymous', 'anonymous', 'module-target@example.test'),
                                         ('local', 'module_target', 'module-target-password')]:
            with ftplib.FTP(timeout=3) as client:
                banner = client.connect(endpoints[relay]['host'], endpoints[relay]['port'])
                assert banner.startswith('220 ') and 'ProFTPD' in banner
                login = client.login(username, password)
                chunks = []
                client.retrbinary('RETR module-target.txt', chunks.append)
                assert b''.join(chunks) == b'module-target-ftp-marker\n'
                attempts = []
                for port in [8080, 8082, 8081, 80]:
                    port_response = command(client, 'PORT ' + port_argument(port))
                    row = {'port': port, 'PORT': port_response}
                    if relay == 'protected' or port == 80:
                        assert port_response.startswith('500 '), row
                    else:
                        assert port_response.startswith('200 '), row
                        listing = command(client, 'LIST')
                        row['LIST'] = listing
                        if port == 8081:
                            assert listing.startswith('425 '), row
                        else:
                            assert listing.startswith(('125 ', '150 ')), row
                            completion = client.voidresp()
                            row['completion'] = completion
                            assert completion.startswith('226 '), row
                    attempts.append(row)
                profiles[name] = {'banner': banner, 'login': login, 'exact_retrieval': True, 'attempts': attempts}
        with ftplib.FTP(timeout=3) as client:
            client.connect(endpoints[relay]['host'], endpoints[relay]['port'])
            try:
                client.login('module_target', 'wrong-password')
            except ftplib.error_perm as error:
                assert str(error).startswith('530 ')
                profiles['invalid_login'] = str(error)
            else:
                raise AssertionError('Invalid FTP password accepted')
        result['profiles'][relay] = profiles
    assert sorted(path.name for path in Path('/srv/ftp').iterdir()) == ['module-target.txt']
    assert Path('/srv/ftp/module-target.txt').read_bytes() == b'module-target-ftp-marker\n'
    result['status'] = 'native_passed'
except Exception as error:
    result['error'] = {'class': type(error).__name__, 'message': str(error), 'traceback': traceback.format_exc()}
finally:
    print(json.dumps(result, indent=2))
sys.exit(0 if result['status'] == 'native_passed' else 1)
