"""Real mc/S3 and separate raw HTTP controls; never supplies a target handler."""
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request
import uuid


class Native:
    def __init__(self, runtime):
        self.runtime = runtime
        self.assets = json.loads(Path(runtime['assets']).read_text())
        self.settings = self.assets['native']
        self.commands = []
        self.requests = []
        self.facts = {}
        self.nonce = uuid.uuid4().hex
        self.config = '/tmp/module-target-minio-' + self.nonce
        self.proof = self.config + '-proof'
        self.bucket = 'module-target-' + self.nonce
        self.config_owned = set()
        self.bucket_attempted = False
        self.client = '/usr/local/bin/mc'
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))

    def journal(self, name, record):
        with (Path(self.runtime['artifacts']) / name).open('a') as file:
            file.write(json.dumps(record) + '\n')

    def command(self, service, *args, expected=0, stdin=None):
        argv = self.runtime['compose'] + ['exec', '-T', service, *args]
        record = dict(argv=argv, exitstatus=None, stdout='', stderr='',
                      stdin_sha256=None if stdin is None else hashlib.sha256(stdin).hexdigest())
        self.commands.append(record)
        self.journal('native-command-attempts.jsonl', record)
        try:
            result = subprocess.run(argv, input=stdin, capture_output=True,
                                    timeout=self.settings['command_seconds'],
                                    env={**os.environ, **self.runtime['compose_environment']})
        except subprocess.TimeoutExpired as error:
            record.update(stdout=(error.stdout or b'').decode('utf-8', errors='replace'),
                          stderr=(error.stderr or b'').decode('utf-8', errors='replace'),
                          error='Command exceeded its native bound')
            self.journal('native-commands.jsonl', record)
            raise
        record.update(exitstatus=result.returncode,
                      stdout=result.stdout.decode('utf-8', errors='replace'),
                      stderr=result.stderr.decode('utf-8', errors='replace'))
        self.journal('native-commands.jsonl', record)
        if expected is not None:
            assert result.returncode == expected, record
        return result.stdout, result.returncode

    def mc(self, *args, service='node1', json_mode=True, expected=0, environment=None):
        argv = [] if environment is None else ['env', *[f'{key}={value}' for key, value in environment.items()]]
        argv += [self.client, '--config-dir', self.config]
        if json_mode:
            argv.append('--json')
        return self.command(service, *argv, *args, expected=expected)

    @staticmethod
    def documents(raw):
        return [json.loads(line) for line in raw.decode().splitlines() if line.strip()]

    def request(self, service, path, method='GET'):
        endpoint = self.runtime['endpoints'][service]
        url = f"http://{endpoint['host']}:{endpoint['port']}{path}"
        record = dict(url=url, method=method, status=None, headers={}, body=None)
        self.requests.append(record)
        self.journal('native-http-attempts.jsonl', record)
        try:
            try:
                response = self.opener.open(urllib.request.Request(url, data=b'' if method == 'POST' else None,
                                                                 method=method), timeout=self.settings['command_seconds'])
            except urllib.error.HTTPError as error:
                response = error
        except (urllib.error.URLError, TimeoutError, OSError) as error:
            record['transport_error'] = dict(type=type(error).__name__, message=str(error))
            self.journal('native-http.jsonl', record)
            raise
        with response:
            record.update(status=response.status, headers=dict(response.headers),
                          body=response.read().decode('utf-8'))
        self.journal('native-http.jsonl', record)
        return record

    def initialize_client(self):
        # Actual CLI initializes its valid vendor config; remove sample/cloud
        # aliases on BOTH nodes before any S3 operation, without contacting them.
        guards = self.facts.setdefault('fresh_owned_config_guards', {})
        for service in self.settings['services']:
            self.command(service, 'sh', '-c',
                         'test ! -e "$1" && test ! -L "$1" && test ! -e "$2" && test ! -L "$2"',
                         'sh', self.config, self.proof)
            self.config_owned.add(service)
            guards[service] = dict(config=self.config, proof=self.proof, initially_absent=True)
            self.mc('alias', 'list', service=service)
            raw, _ = self.command(service, 'cat', self.config + '/config.json')
            aliases = json.loads(raw)['aliases']
            for name in aliases:
                self.mc('alias', 'rm', name, service=service)
            raw, _ = self.command(service, 'cat', self.config + '/config.json')
            assert json.loads(raw)['aliases'] == {}
        port = self.settings['api_port']
        for service in self.settings['services']:
            self.mc('alias', 'set', 'lab', f'http://{service}:{port}',
                    self.settings['root_user'], self.settings['root_password'],
                    '--api', 'S3v4', '--path', 'auto', service=service)

    def cleanup(self, baseline):
        """Attempt every owned node even when another cleanup/probe fails."""
        errors = []
        self.facts['restored'] = False
        absent = self.facts.setdefault('cleanup_absence', {})
        logical_restored = False

        def attempt(operation, action):
            try:
                action()
            except Exception as error:
                errors.append(dict(operation=operation, type=type(error).__name__, message=str(error)))

        def bucket_cleanup():
            if self.bucket in self.bucket_names():
                # This pinned client's single-object rm --force rejects absent
                # objects. List first and remove only the known owned keys.
                raw, _ = self.mc('ls', 'lab/' + self.bucket + '/')
                rows = self.documents(raw)
                assert all(isinstance(row, dict) and row.get('status') == 'success'
                           and row.get('type') in ('file', 'folder')
                           and isinstance(row.get('key'), str) for row in rows), rows
                keys = {row['key'] for row in rows if row['type'] == 'file'}
                for index in range(2):
                    key = f'proof-{index}.txt'
                    if key in keys:
                        attempt(f'owned-s3-object-{index}',
                                lambda key=key: self.mc('rm', '--force', f'lab/{self.bucket}/{key}'))
                self.mc('rb', 'lab/' + self.bucket)

        def probe(service, kind, path):
            self.command(service, 'sh', '-c', 'test ! -e "$1" && test ! -L "$1"', 'sh', path)
            absent.setdefault(service, {})[kind] = True

        def restore_logical():
            nonlocal logical_restored
            restored = self.snapshot()
            assert restored == baseline, dict(before=baseline, after=restored)
            self.facts['baseline'] = baseline
            logical_restored = True

        if self.bucket_attempted:
            attempt('owned-s3-bucket', bucket_cleanup)
        for service in self.settings['services']:
            if service not in self.config_owned:
                continue
            attempt(service + '-remove-proof', lambda service=service: self.command(service, 'rm', '-f', '--', self.proof))
            attempt(service + '-proof-absence', lambda service=service: probe(service, 'proof', self.proof))
        if baseline is not None:
            attempt('logical-metadata-restoration', restore_logical)
        for service in self.settings['services']:
            if service not in self.config_owned:
                continue
            # The complete config tree (sessions/share/certs included) was
            # absent before this invocation's real mc command created it.
            assert re.fullmatch(r'/tmp/module-target-minio-[0-9a-f]{32}', self.config)
            attempt(service + '-remove-config', lambda service=service: self.command(service, 'rm', '-rf', '--', self.config))
            attempt(service + '-config-absence', lambda service=service: probe(service, 'config', self.config))
        expected = set(self.settings['services'])
        all_absent = self.config_owned == expected and set(absent) == expected and all(
            values == dict(config=True, proof=True) for values in absent.values())
        self.facts['cleanup_errors'] = errors
        self.facts['restored'] = logical_restored and all_absent and not errors
        return errors

    def bucket_names(self):
        raw, _ = self.mc('ls', 'lab')
        rows = self.documents(raw)
        assert all(row['status'] == 'success' for row in rows), rows
        return sorted(row['key'].rstrip('/') for row in rows)

    def snapshot(self):
        servers = []
        drive_ids = set()
        for service in self.settings['services']:
            raw, _ = self.mc('admin', 'info', 'lab', service=service,
                             environment={'MC_HOST_lab': self.alias_url(service)})
            info_rows = [row for row in self.documents(raw) if 'info' in row]
            assert len(info_rows) == 1 and info_rows[0]['status'] == 'success', info_rows
            info = info_rows[0]['info']
            assert info['mode'] == 'online' and len(info['servers']) == 2, info
            assert info['backend']['onlineDisks'] == 4 and info['backend']['offlineDisks'] == 0, info
            normalized = []
            for server in info['servers']:
                assert server['state'] == 'online' and len(server['drives']) == 2, server
                assert server['commitID'] == self.assets['sources'][self.runtime['profile']]['commit'], server
                for drive in server['drives']:
                    assert drive['state'] == 'ok' and drive['uuid'], drive
                    drive_ids.add(drive['uuid'])
                normalized.append(dict(endpoint=server['endpoint'], state=server['state'],
                                       commit=server['commitID'],
                                       drives=sorted((drive['uuid'], drive['endpoint'], drive['state'])
                                                     for drive in server['drives'])))
            servers.append(dict(deployment=info['deploymentID'], servers=sorted(normalized, key=lambda row: row['endpoint'])))
            assert self.request(service, self.settings['health_path'])['status'] == 200
        assert len(drive_ids) == 4 and servers[0] == servers[1], servers
        formats = {}
        for service in self.settings['services']:
            for drive in self.settings['drives']:
                raw, _ = self.command(service, 'cat', drive + '/.minio.sys/format.json')
                formats[service + drive] = json.loads(raw)
        format_ids = {value['xl']['this'] for value in formats.values()}
        assert len(format_ids) == 4 and format_ids == drive_ids, formats
        # Preserve stable identity/format and logical buckets. Admin uptime,
        # scanner counters, audit timestamps and whole-disk bytes are excluded.
        return dict(cluster=servers[0], formats=formats, buckets=self.bucket_names())

    def alias_url(self, service, password=None):
        user = urllib.parse.quote(self.settings['root_user'], safe='')
        secret = urllib.parse.quote(password or self.settings['root_password'], safe='')
        return f"http://{user}:{secret}@{service}:{self.settings['api_port']}"

    def versions(self):
        for service in self.settings['services']:
            raw, _ = self.command(service, 'sha256sum', '/usr/local/bin/minio', self.client)
            actual = dict(line.split()[::-1] for line in raw.decode().splitlines())
            server = self.assets['sources'][self.runtime['profile']]
            assert actual['/usr/local/bin/minio'] == server['reference']['binary_sha256']
            assert actual[self.client] == self.assets['sources']['client']['reference']['binary_sha256']
            for name, source in [('minio', server), ('mc', self.assets['sources']['client'])]:
                output, _ = self.command(service, '/usr/local/bin/' + name, '--version')
                text = output.decode()
                assert source['tag'] in text and source['commit'] in text and self.assets['build']['toolchain'] in text
            raw, _ = self.command(service, 'uname', '-m')
            assert raw.strip() == b'x86_64'

    def run(self):
        baseline = None
        try:
            self.versions()
            self.initialize_client()
            baseline = self.snapshot()
            assert self.bucket not in baseline['buckets']
            bad, code = self.mc('ls', 'rejected', expected=None,
                                environment={'MC_HOST_rejected': self.alias_url('node1', 'incorrect-password')})
            last = self.commands[-1]
            assert code != 0 and re.search(r'\b(?:AccessDenied|SignatureDoesNotMatch|InvalidAccessKeyId)\b',
                                            bad.decode(errors='replace') + last['stderr']), last
            self.bucket_attempted = True
            self.mc('mb', 'lab/' + self.bucket)
            for index in range(2):
                proof = f"MinIO native exact + $HOME; 'quoted' café {index} {self.nonce}".encode()
                self.command('node1', 'sh', '-c', 'umask 077; cat > "$1"', 'sh', self.proof, stdin=proof)
                target = f'lab/{self.bucket}/proof-{index}.txt'
                self.mc('cp', self.proof, target)
                raw, _ = self.mc('stat', target)
                assert any(row.get('size') == len(proof) for row in self.documents(raw))
                raw, _ = self.mc('cat', target, json_mode=False)
                assert raw == proof
                self.mc('rm', target)
            disclosures = {}
            for service in self.settings['services']:
                response = self.request(service, self.settings['bootstrap_path'], 'POST')
                disclosures[service] = response
                if self.runtime['profile'] == 'vulnerable':
                    assert response['status'] == 200, response
                    environment = json.loads(response['body'])['MinioEnv']
                    assert environment['MINIO_ROOT_USER'] == self.settings['root_user']
                    assert environment['MINIO_ROOT_PASSWORD'] == self.settings['root_password']
                    assert environment[self.settings['sentinel_key']] == self.settings['sentinel_value']
                    assert self.settings['excluded_key'] not in environment
                    self.mc('alias', 'set', 'disclosed', f"http://{service}:{self.settings['api_port']}",
                            environment['MINIO_ROOT_USER'], environment['MINIO_ROOT_PASSWORD'])
                    self.mc('ls', 'disclosed')
                    self.mc('alias', 'rm', 'disclosed')
                else:
                    assert response['status'] == 403 and 'MINIO_ROOT_PASSWORD' not in response['body'], response
            self.facts['bootstrap'] = disclosures
        finally:
            cleanup_errors = self.cleanup(baseline)
            path = Path(self.runtime['artifacts']) / 'native-control.json'
            path.write_text(json.dumps(dict(commands=self.commands, requests=self.requests, facts=self.facts), indent=2) + '\n')
            assert not cleanup_errors, cleanup_errors
        assert self.facts.get('restored') is True
        return dict(status='native_passed', restored=True, cli_commands=len(self.commands),
                    http_requests=len(self.requests), framework_console_module_calls=0)


if __name__ == '__main__':
    print(json.dumps(Native(json.loads(Path(sys.argv[1]).read_text())).run()))
