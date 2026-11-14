"""Independent vendor JDBC and web controls; all requests and commands are saved."""
from pathlib import Path
import base64
import json
import os
import re
import subprocess
import sys
import urllib.parse
import urllib.request


class Native:
    def __init__(self, tag):
        self.runtime = json.loads(Path(os.environ['MODULE_TARGET_RUNTIME']).read_text())
        self.version = os.environ['H2_VERSION']
        self.tag = tag
        self.journal = []

    def command(self, *arguments):
        argv = self.runtime['compose'] + list(arguments)
        result = subprocess.run(argv, capture_output=True, timeout=30)
        self.journal.append(dict(argv=argv, actual_exit=result.returncode,
                                 stdout_base64=base64.b64encode(result.stdout).decode(),
                                 stderr_base64=base64.b64encode(result.stderr).decode()))
        self.save()
        if result.returncode:
            raise RuntimeError(result.stderr.decode(errors='replace'))
        return result.stdout

    def execute(self, *arguments):
        return self.command('exec', '-T', 'target', *arguments)

    def jdbc(self, action, user='sa', sql=None):
        arguments = ['java', '-Xms16m', '-Xmx48m', '-XX:+UseSerialGC', '-XX:ActiveProcessorCount=1',
                     '-cp', '.:vendor/h2-' + self.version + '.jar', 'NativeControl', action, user]
        if sql is not None:
            arguments.append(sql)
        raw = self.execute(*arguments)
        return [base64.b64decode(line.split(b'=', 1)[1]).decode() for line in raw.splitlines()]

    def http(self, port, path, data=None):
        address = self.command('port', 'target', str(port)).decode().strip().rsplit(':', 1)[1]
        url = 'http://127.0.0.1:' + address + '/' + path
        payload = urllib.parse.urlencode(data).encode() if data is not None else None
        with urllib.request.urlopen(url, payload, timeout=10) as response:
            body = response.read()
            self.journal.append(dict(url=url, data=data, status=response.status,
                                     body_base64=base64.b64encode(body).decode()))
        self.save()
        return body.decode()

    def save(self):
        path = Path(self.runtime['artifacts']) / ('native-' + self.tag + '.json')
        path.write_text(json.dumps(self.journal, indent=2) + '\n')

    def aliases(self):
        if self.version.startswith('1.'):
            sql = "SELECT ALIAS_NAME FROM INFORMATION_SCHEMA.FUNCTION_ALIASES WHERE ALIAS_SCHEMA='PUBLIC' ORDER BY ALIAS_NAME"
        else:
            sql = "SELECT ROUTINE_NAME FROM INFORMATION_SCHEMA.ROUTINES WHERE ROUTINE_SCHEMA='PUBLIC' ORDER BY ROUTINE_NAME"
        return self.jdbc('query', sql=sql)

    def verify(self):
        self.execute('java', '-version')
        java = base64.b64decode(self.journal[-1]['stderr_base64']).decode()
        assert '1.8.0_' in java
        python = self.execute('python3', '-c', 'import sys; assert sys.version_info.major == 3; print(sys.version)').decode().strip()
        identity = self.execute('id').decode().strip()
        assert identity.startswith('uid=1000(target) gid=1000(target)')
        processes = json.loads(self.execute('python3', '/opt/module-target/process_state.py'))['processes']
        engines = [row for row in processes if row['command'].endswith('vendor/h2-' + self.version + '.jar Bootstrap')]
        assert len(engines) == 1 and engines[0]['uid'] == '1000'
        startup = {key: value for key, value in engines[0].items() if key != 'state'}
        packages = self.execute('dpkg-query', '-W', '-f=${Package}\t${Version}\t${Architecture}\n', 'python3', 'curl').decode()
        verification = self.execute('dpkg', '--verify', 'python3', 'curl').decode()
        binaries = self.execute('sha256sum', '/usr/bin/python3', '/usr/bin/curl').decode()
        artifacts = json.loads(Path(__file__).with_name('vendor.json').read_text())['artifacts']
        artifact = next(row for row in artifacts if row['version'] == self.version)
        digest = self.execute('sha256sum', 'vendor/' + artifact['file']).decode().split()[0]
        assert digest == artifact['sha256']
        assert self.jdbc('query', sql='SELECT H2VERSION(), VALUE_TEXT FROM MODULE_CANARY WHERE ID=1') == [self.version + '\tmodule-target-h2-canary']
        assert self.jdbc('proof') == ['module-target-native-h2']
        assert self.jdbc('proof', 'reader')[0].startswith('90040:')
        for port in (8082, 8083):
            initial = self.http(port, 'login.jsp')
            sid = re.search(r"location.href = 'login.jsp\?jsessionid=([^']+)';", initial).group(1)
            assert '<title>H2 Console</title>' in self.http(port, 'login.jsp?jsessionid=' + sid)
            def fields(database, user, password):
                return dict(language='en', setting='Generic H2 (Embedded)', name='Generic H2 (Embedded)',
                            driver='org.h2.Driver', url=database, user=user, password=password)
            for user, password, allowed in [('sa', 'module-target-admin', True), ('reader', 'module-target-reader', True), ('sa', 'module-target-wrong', False)]:
                body = self.http(port, 'test.do?jsessionid=' + sid, fields('jdbc:h2:./state/known', user, password))
                assert ('Test successful' in body) == allowed
            body = self.http(port, 'test.do?jsessionid=' + sid, fields('jdbc:h2:mem:module_native_' + str(port), '', ''))
            assert ('Test successful' in body) == (port == 8082)
            self.http(port, 'login.do?jsessionid=' + sid, fields('jdbc:h2:./state/known', 'sa', 'module-target-admin'))
            body = self.http(port, 'query.do?jsessionid=' + sid, dict(sql='SELECT H2VERSION(), VALUE_TEXT FROM MODULE_CANARY;'))
            assert self.version in body and 'module-target-h2-canary' in body
            alias = 'MODULE_NATIVE_HTTP_' + str(port)
            try:
                self.http(port, 'query.do?jsessionid=' + sid, dict(sql='CREATE ALIAS ' + alias + ' AS $$ String proof() { return "native-http-proof"; } $$;'))
                assert self.aliases() == [alias]
                body = self.http(port, 'query.do?jsessionid=' + sid, dict(sql='CALL ' + alias + '();'))
                assert 'native-http-proof' in body
                assert self.jdbc('query', sql='CALL ' + alias + '()') == ['native-http-proof']
            finally:
                self.http(port, 'query.do?jsessionid=' + sid, dict(sql='DROP ALIAS IF EXISTS ' + alias + ';'))
            assert self.aliases() == []
            self.http(port, 'logout.do?jsessionid=' + sid)
            self.http(port, 'login.do?jsessionid=' + sid, fields('jdbc:h2:./state/known', 'reader', 'module-target-reader'))
            body = self.http(port, 'query.do?jsessionid=' + sid, dict(sql='CREATE ALIAS ' + alias + ' AS $$ String proof() { return "denied"; } $$;'))
            assert '90040' in body
            self.http(port, 'logout.do?jsessionid=' + sid)
        assert self.aliases() == []
        return dict(version=self.version, jar_sha256=digest, java=java, python=python, identity=identity, startup=startup, packages=packages, package_verification=verification, binaries=binaries, admin_execution=True, reader_denied=True,
                    wrong_password_denied=True, no_create_policy=True, aliases_after=[])


if __name__ == '__main__':
    action, tag, *arguments = sys.argv[1:]
    if not re.fullmatch(r'[a-z0-9_-]+', tag):
        raise ValueError('Invalid artifact tag')
    native = Native(tag)
    if action == 'verify':
        result = native.verify()
    elif action == 'aliases':
        result = native.aliases()
    else:
        raise ValueError('Unknown action')
    print(json.dumps(result))
