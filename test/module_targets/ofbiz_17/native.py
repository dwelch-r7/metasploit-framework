"""Calibrate real OFBiz services independently of Framework module output."""
from pathlib import Path
import base64
import hashlib
import html
import http.cookiejar
import json
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request
import xmlrpc.client


PROFILE = json.loads(Path(__file__).with_name('releases.json').read_text())['profiles'][sys.argv[1]]
ROOT = Path('/usr/src/apache-ofbiz')


def snapshot():
    files = {name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest()
             for name in PROFILE['source_files']}
    processes = []
    for entry in Path('/proc').iterdir():
        if not entry.name.isdigit():
            continue
        try:
            command = (entry / 'cmdline').read_bytes()
            if command.startswith(b'java\x00') and b'ofbiz.jar' in command:
                processes.append({'pid': int(entry.name),
                                  'starttime': (entry / 'stat').read_text().rsplit(')', 1)[1].split()[19],
                                  'command_base64': base64.b64encode(command).decode()})
        except (FileNotFoundError, ProcessLookupError):
            continue
    return {'files': files, 'java_processes': processes,
            'proof_paths': sorted(str(path) for path in Path('/tmp').glob('module-target-ofbiz-*'))}


def audit():
    context = ssl._create_unverified_context()  # The upstream lab has a self-signed certificate.
    responses, checks = [], []

    def client():
        return urllib.request.build_opener(
            urllib.request.HTTPSHandler(context=context),
            urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))

    guest, authenticated = client(), client()

    def check(name, passed):
        checks.append({'name': name, 'passed': bool(passed)})

    def request(label, path, data=None, session=guest, content_type='application/x-www-form-urlencoded'):
        query = urllib.request.Request('https://127.0.0.1:8443' + path, data=data,
                                       headers={'Host': 'localhost', 'Content-Type': content_type})
        try:
            response = session.open(query, timeout=30)
        except urllib.error.HTTPError as error:
            response = error
        body = response.read()
        responses.append({'label': label, 'path': path, 'code': response.code,
                          'body_base64': base64.b64encode(body).decode()})
        return body.decode(errors='replace')

    state = snapshot()
    check('archived-source-and-documented-host-header-patch', state['files'] == PROFILE['source_files'])
    check('one-live-ofbiz-jvm', len(state['java_processes']) == 1)
    check('no-leftover-proof-paths', not state['proof_paths'])
    main = request('ordinary-public-main', '/webtools/control/main')
    check('genuine-ofbiz-main', 'Apache OFBiz.' in main and 'Web Tools' in main)
    denied = request('ordinary-protected-page-denied', '/webtools/control/entitymaint')
    check('guest-has-login-form', 'name="USERNAME"' in denied and 'logout' not in denied)
    invalid = request('ordinary-absent-account-denied', '/webtools/control/login',
                      urllib.parse.urlencode({'USERNAME': 'module_target_absent', 'PASSWORD': 'module-target-invalid', 'JavaScriptEnabled': 'Y'}).encode())
    check('absent-account-has-login-form', 'name="USERNAME"' in invalid and 'logout' not in invalid)
    login = request('ordinary-admin-login', '/webtools/control/login',
                    urllib.parse.urlencode({'USERNAME': 'admin', 'PASSWORD': 'ofbiz', 'JavaScriptEnabled': 'Y'}).encode(), session=authenticated)
    check('native-admin-login', 'logout' in login and 'name="USERNAME"' not in login)
    entities = request('ordinary-native-entity-list', '/webtools/control/entitymaint', session=authenticated)
    check('native-entity-engine', 'UserLogin' in entities and 'logout' in entities)

    message = 'module-target-ofbiz-native-ping'
    ping = xmlrpc.client.dumps(({'message': message},), methodname='ping').encode()
    rpc = request('ordinary-authenticated-xmlrpc-ping', '/webtools/control/xmlrpc', ping,
                  session=authenticated, content_type='text/xml')
    if PROFILE['xmlrpc']:
        check('ordinary-xmlrpc-service', xmlrpc.client.loads(rpc)[0] == ({'message': message},))
        guest_rpc = request('ordinary-guest-xmlrpc-ping', '/webtools/control/xmlrpc', ping, content_type='text/xml')
        check('native-xmlrpc-authentication-contrast',
              message in guest_rpc if PROFILE['legacy_xmlrpc'] else 'name="USERNAME"' in guest_rpc)
        path = '/webtools/control/xmlrpc'
        if not PROFILE['legacy_xmlrpc']:
            path += ';/?USERNAME=&PASSWORD=native&requirePasswordChange=Y'
        # Java Object Serialization TC_STRING: stream header, tag, unsigned UTF-8 length, ASCII bytes.
        # https://docs.oracle.com/javase/8/docs/platform/serialization/spec/protocol.html
        serialized = b'\xac\xed\x00\x05\x74' + len(message).to_bytes(2, 'big') + message.encode()
        body = ('<?xml version="1.0"?><methodCall><methodName>ping</methodName><params><param><value><struct>'
                '<member><name>message</name><value><serializable xmlns="http://ws.apache.org/xmlrpc/namespaces/extensions">'
                + base64.b64encode(serialized).decode() + '</serializable></value></member>'
                '</struct></value></param></params></methodCall>').encode()
        result = request('native-serialized-string-ping', path, body, content_type='text/xml')
        check('native-xmlrpc-string-deserialization', xmlrpc.client.loads(result)[0] == ({'message': message},))
    else:
        check('xmlrpc-is-removed', 'Unknown request [xmlrpc]' in html.unescape(rpc))

    soap = ('<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">'
            '<soapenv:Header/><soapenv:Body><ping><map-HashMap><map-Entry><map-Key>'
            '<std-String value="message"/></map-Key><map-Value><std-String value="' + message
            + '"/></map-Value></map-Entry></map-HashMap></ping></soapenv:Body></soapenv:Envelope>').encode()
    result = request('ordinary-soap-ping', '/webtools/control/SOAPService', soap, content_type='text/xml')
    check('native-soap-service-or-removal', message in result if PROFILE['soap']
          else 'Unknown request [SOAPService]' in html.unescape(result))

    proof = Path('/tmp/module-target-ofbiz-native-proof')
    program = ("new File('/tmp/module-target-ofbiz-native-proof').text='ofbiz-native';"
               "throw new Exception('module-target-ofbiz-native:'+System.getProperty('user.name'))")
    escaped = ''.join('\\u%04x' % ord(char) for char in program)
    form = urllib.parse.urlencode({'groovyProgram': escaped}).encode()
    try:
        request('native-direct-export-denied', '/webtools/control/ProgramExport', form)
        check('direct-protected-export-refuses-write', not proof.exists())
        if proof.exists():
            proof.unlink()
        result = request('native-unauthenticated-export', '/webtools/control/forgotPassword/ProgramExport', form)
        evidence = {'exists': proof.exists(), 'uid': proof.stat().st_uid if proof.exists() else None,
                    'base64': base64.b64encode(proof.read_bytes()).decode() if proof.exists() else None}
        check('native-program-export-release-contrast',
              evidence == {'exists': True, 'uid': 0, 'base64': base64.b64encode(b'ofbiz-native').decode()}
              and 'module-target-ofbiz-native:root' in result if PROFILE['program_export'] else not evidence['exists'])
    finally:
        if proof.exists():
            proof.unlink()
    check('native-proof-cleaned', not proof.exists())
    return {'profile': sys.argv[1], 'version': PROFILE['version'], 'checks': checks, 'http': responses,
            'export_proof': evidence, 'snapshot': snapshot(), 'passed': all(row['passed'] for row in checks)}


if len(sys.argv) > 2 and sys.argv[2] == 'snapshot':
    print(json.dumps(snapshot()))
else:
    result = audit()
    print(json.dumps(result))
    sys.exit(0 if result['passed'] else 1)
