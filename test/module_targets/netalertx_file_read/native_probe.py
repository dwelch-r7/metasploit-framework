"""Independent native HTTP, authentication, source and initialized DB controls."""
import base64
import hashlib
from html.parser import HTMLParser
import http.cookiejar
import json
import os
from pathlib import Path
import subprocess
import urllib.error
import urllib.parse
import urllib.request

CONTENT = 'NetAlertX native proof\n<node>& "quoted"\nsecond line\n'
PROOF_ROOT = '/tmp/module-target-netalertx/'


class Textarea(HTMLParser):
    def __init__(self, body):
        super().__init__(convert_charrefs=True)
        self.inside = False
        self.found = False
        self.content = ''
        self.feed(body)

    def handle_starttag(self, tag, attrs):
        if tag == 'textarea':
            self.inside = True
            self.found = True

    def handle_endtag(self, tag):
        if tag == 'textarea':
            self.inside = False

    def handle_data(self, data):
        if self.inside:
            self.content += data


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, file, code, message, headers, url):
        return None


class NativeNetalertx:
    def __init__(self, runtime):
        self.runtime = runtime
        endpoint = runtime['endpoints']['target']
        self.origin = 'http://' + endpoint['host'] + ':' + str(endpoint['port'])
        self.events = []
        self.commands = []
        self.anonymous = urllib.request.build_opener(NoRedirect())
        self.authenticated = urllib.request.build_opener(NoRedirect(), urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))

    def command(self, *arguments):
        argv = self.runtime['compose'] + ['exec', '-T', 'target'] + list(arguments)
        result = subprocess.run(argv, capture_output=True, text=True, timeout=30)
        self.commands.append(dict(argv=argv, exitstatus=result.returncode, stdout=result.stdout, stderr=result.stderr))
        assert result.returncode == 0, self.commands[-1]
        return result.stdout

    def request(self, path, form=None, authenticated=False):
        data = urllib.parse.urlencode(form).encode() if form is not None else None
        request = urllib.request.Request(self.origin + path, data=data)
        opener = self.authenticated if authenticated else self.anonymous
        try:
            response = opener.open(request, timeout=10)
        except urllib.error.HTTPError as error:
            response = error
        with response:
            body = response.read()
            event = dict(path=path, form=form, authenticated=authenticated, status=response.code,
                         headers=dict(response.headers), body_base64=base64.b64encode(body).decode())
        self.events.append(event)
        return event, body.decode('utf-8')

    def read(self, name, authenticated=False):
        item = dict(fileName='native-proof', filePath=PROOF_ROOT + name, textAreaCssClass='logs', buttons=[])
        response, body = self.request('/php/components/logs.php', {'items': json.dumps([item])}, authenticated)
        parsed = Textarea(body)
        return response, parsed

    def verify(self, version, protected):
        bootstrap = json.loads(self.command('cat', '/tmp/module-target-netalertx-bootstrap.json'))
        assert bootstrap['version'] == 'v' + version and bootstrap['web_protection'] == protected
        catalog = json.loads(Path(__file__).with_name('vendor.json').read_text())[version]
        code = "import hashlib,json,pathlib,sys; paths=json.loads(sys.argv[1]); print(json.dumps({p:hashlib.sha256((pathlib.Path('/app')/p).read_bytes()).hexdigest() for p in paths}))"
        hashes = json.loads(self.command('python', '-c', code, json.dumps(list(catalog['files_sha256']))))
        assert hashes == catalog['files_sha256']
        response, body = self.request('/index.php')
        if protected:
            assert response['status'] == 200 and 'name="loginpassword"' in body
            bad, _ = self.request('/index.php', {'loginpassword': 'module-target-wrong'}, authenticated=True)
            assert bad['status'] == 200 and not bad['headers'].get('Location', '').endswith('devices.php')
            good, _ = self.request('/index.php', {'loginpassword': 'module-target-netalertx-password'}, authenticated=True)
            assert good['status'] == 302 and good['headers']['Location'].endswith('devices.php')
        else:
            assert response['status'] == 302 and response['headers']['Location'].endswith('devices.php')
        maintenance, body = self.request('/maintenance.php', authenticated=True)
        if not protected:
            # With protection disabled, the ordinary endpoint needs no login.
            maintenance, body = self.request('/maintenance.php')
        assert maintenance['status'] == 200 and 'v' + version in body
        exposed = version == '24.9.12' or not protected
        anonymous, parsed = self.read('proof.txt')
        assert (parsed.found and parsed.content == CONTENT) == exposed
        assert anonymous['status'] == (200 if exposed else 302)
        for name in ['proof.txt', 'space name.txt', 'quote"name.txt']:
            response, parsed = self.read(name, authenticated=protected)
            assert response['status'] == 200 and parsed.found and parsed.content == CONTENT, (name, response, parsed.content)
        for name in ['missing.txt', 'empty.txt']:
            response, parsed = self.read(name, authenticated=protected)
            assert response['status'] == 200 and parsed.found and parsed.content == ''
        database = json.loads(self.command('python', '-c', "import sqlite3,json; c=sqlite3.connect('file:/app/db/app.db?mode=ro',uri=True); print(json.dumps(dict(integrity=c.execute('pragma integrity_check').fetchone()[0],settings=c.execute('select count(*) from Settings').fetchone()[0],language=c.execute(\"select Value from Settings where Code_Name='UI_LANG'\").fetchone()[0])))"))
        assert database['integrity'] == 'ok' and database['settings'] > 0 and database['language'] == 'English'
        processes = self.command('ps', '-o', 'pid,comm,args')
        assert '/app/server' not in processes and 'crond' not in processes and 'arp-scan' not in processes
        memory = self.command('cat', '/sys/fs/cgroup/memory.events')
        assert 'oom 0\n' in memory and 'oom_kill 0\n' in memory
        assert self.command('cat', '/sys/fs/cgroup/pids.events').strip() == 'max 0'
        return dict(version=version, protected=protected, exposed=exposed, bootstrap=bootstrap,
                    source_hashes=hashes, database=database, processes=processes,
                    anonymous_maintenance_status=self.request('/maintenance.php')[0]['status'])


if __name__ == '__main__':
    runtime = json.loads(Path(os.environ['MODULE_TARGET_RUNTIME']).read_text())
    client = NativeNetalertx(runtime)
    artifacts = Path(runtime['artifacts'])
    proof = {}
    try:
        proof = client.verify(os.environ['NETALERTX_VERSION'], os.environ['NETALERTX_PROTECTED'] == 'true')
    finally:
        (artifacts / 'native-netalertx.json').write_text(json.dumps(dict(proof=proof, requests=client.events, commands=client.commands), indent=2) + '\n')
    print(json.dumps(proof))
