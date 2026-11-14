"""Direct HugeGraph controls, independent of the Metasploit owner and payload."""
from pathlib import Path
import base64
import gzip
import json
import os
import re
import subprocess
import sys
import urllib.error
import urllib.request


class Native:
    def __init__(self, tag):
        self.runtime = json.loads(Path(os.environ['MODULE_TARGET_RUNTIME']).read_text())
        self.version = os.environ['HG_VERSION']
        self.prefix = os.environ.get('HG_PREFIX', '')
        self.protected = os.environ.get('HG_AUTH') == 'config'
        self.tag = tag
        self.journal = []

    def save(self):
        destination = Path(self.runtime['artifacts']) / ('native-' + self.tag + '.json')
        destination.write_text(json.dumps(self.journal, indent=2) + '\n')

    def command(self, *arguments):
        argv = self.runtime['compose'] + list(arguments)
        result = subprocess.run(argv, capture_output=True, timeout=30)
        self.journal.append(dict(argv=argv, actual_exit=result.returncode,
                                 stdout_base64=base64.b64encode(result.stdout).decode(),
                                 stderr_base64=base64.b64encode(result.stderr).decode()))
        self.save()
        if result.returncode:
            raise RuntimeError(result.stderr.decode(errors='replace'))
        return result.stdout

    def execute(self, *arguments):
        return self.command('exec', '-T', 'target', *arguments)

    def http(self, path, script=None, authenticated=True):
        port = self.command('port', 'target', '8080').decode().strip().rsplit(':', 1)[1]
        url = 'http://127.0.0.1:' + port + self.prefix + path
        headers = {'Content-Type': 'application/json'}
        if self.protected and authenticated:
            headers['Authorization'] = 'Basic ' + base64.b64encode(b'admin:module-target-admin').decode()
        payload = dict(gremlin=script, bindings={}, language='gremlin-groovy', aliases={}) if script is not None else None
        request = urllib.request.Request(url, data=json.dumps(payload).encode() if payload is not None else None, headers=headers)
        try:
            response = urllib.request.urlopen(request, timeout=15)
        except urllib.error.HTTPError as error:
            response = error
        raw = response.read()
        body = gzip.decompress(raw) if response.headers.get('Content-Encoding', '').lower() == 'gzip' else raw
        self.journal.append(dict(url=url, data=payload, authenticated=authenticated,
                                 status=response.status, headers=dict(response.headers),
                                 body_base64=base64.b64encode(raw).decode(),
                                 decoded_base64=base64.b64encode(body).decode()))
        self.save()
        return response.status, body

    def gremlin(self, script):
        return self.http('/gremlin', script)

    def server_pid(self):
        listing = self.execute('jcmd', '-l').decode()
        engines = [line.split()[0] for line in listing.splitlines() if 'org.apache.hugegraph.dist.HugeGraphServer' in line]
        assert len(engines) == 1, listing
        return engines[0]

    def threads(self):
        dump = self.execute('jcmd', self.server_pid(), 'Thread.print').decode()
        rows = {identifier: name for name, identifier in re.findall(r'^"([^"]+)" #(\d+) ', dump, re.M)
                if name.startswith('gremlin-server-exec-')}
        assert rows, dump
        return rows

    def sandbox(self):
        path = '/tmp/module-target-hugegraph-ordinary'
        self.execute('test', '!', '-e', path)
        script = 'new ProcessBuilder("/bin/sh","-c","printf ordinary-command > ' + path + '").start().waitFor(); "ordinary-complete"'
        status, body = self.gremlin(script)
        try:
            if self.protected:
                assert status == 400 and b'No signature of method: java.lang.ProcessBuilder.start()' in body, (status, body)
            else:
                assert status == 403 and b'Not allowed to execute command via Gremlin' in body, (status, body)
            self.execute('test', '!', '-e', path)
        finally:
            self.execute('rm', '-f', '--', path)
        return dict(ordinary_command_denied=True, status=status)

    def verify(self):
        self.execute('java', '-version')
        java = base64.b64decode(self.journal[-1]['stderr_base64']).decode()
        assert '11.0.16' in java
        command_line = self.execute('jcmd', self.server_pid(), 'VM.command_line').decode().split('\n', 1)[1]
        assert '-Djava.security.manager=org.apache.hugegraph.security.HugeSecurityManager' in command_line
        assert '-Xms256m' in command_line and '-Xmx384m' in command_line
        original_rest = self.execute('cat', '/tmp/module-target-hugegraph/original-rest.properties').decode()
        current_rest = self.execute('cat', 'conf/rest-server.properties').decode()
        original_limits = [line for line in original_rest.splitlines() if line.startswith('restserver.min_free_memory=')]
        assert [line for line in current_rest.splitlines() if line.startswith('restserver.min_free_memory=')] == original_limits
        self.execute('sha256sum', '-c', '/tmp/module-target-hugegraph/original-jars.sha256')
        jars = self.execute('sha256sum', 'lib/hugegraph-api-' + self.version + '.jar', 'lib/hugegraph-core-' + self.version + '.jar').decode()
        status, body = self.http('/')
        assert status == 200 and json.loads(body)['service'] == 'hugegraph' and json.loads(body)['version'] == self.version
        status, body = self.gremlin('1+1')
        assert status == 200 and json.loads(body)['result']['data'] == [2]
        status, body = self.gremlin('hugegraph.traversal().V().count()')
        assert status == 200 and json.loads(body)['result']['data'] == [0]
        self.sandbox()
        path = '/tmp/module-target-hugegraph-native'
        self.execute('test', '!', '-e', path)
        # Restore the same worker in finally; the negative control must still
        # enforce the vendor sandbox after the proof process has terminated.
        bypass = ('def nativeThread = Thread.currentThread(); '
                  'def nativeField = Class.forName("java.lang.Thread").getDeclaredField("name"); '
                  'nativeField.setAccessible(true); def nativeName = nativeThread.getName(); '
                  'try { nativeField.set(nativeThread, "module_native_control"); '
                  'new ProcessBuilder("/bin/sh","-c","printf native-bypass > ' + path + '").start().waitFor(); '
                  '} finally { nativeField.set(nativeThread,nativeName); }; "bypass-complete"')
        try:
            status, body = self.gremlin(bypass)
            if self.protected:
                assert status == 400 and b'No signature of method: java.lang.Class.forName()' in body, (status, body)
                self.execute('test', '!', '-e', path)
                assert self.http('/gremlin', '1+1', authenticated=False)[0] == 401
            else:
                assert status == 200, body
                assert self.execute('cat', path) == b'native-bypass'
        finally:
            self.execute('rm', '-f', '--', path)
        self.sandbox()
        return dict(version=self.version, prefix=self.prefix, protected=self.protected,
                    java=java, engine_command=command_line, free_memory_configuration=original_limits,
                    graph_count=0, jars_unchanged=True, vendor_jars_sha256=jars,
                    bypass_blocked=self.protected, ordinary_command_denied=True)


if __name__ == '__main__':
    action, tag = sys.argv[1:]
    if not re.fullmatch(r'[a-z0-9_-]+', tag):
        raise ValueError('Invalid artifact tag')
    native = Native(tag)
    if action not in ('verify', 'sandbox', 'threads'):
        raise ValueError('Unknown control')
    print(json.dumps(getattr(native, action)()))
