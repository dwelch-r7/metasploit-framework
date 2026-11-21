"""Independent stdlib client for the actual legacy Node/V8 debugger protocol."""

from pathlib import Path
from email.parser import BytesHeaderParser
import base64
import importlib.util
import json
import os
import socket
import sys
import tempfile

spec = importlib.util.spec_from_file_location('native_base', Path(__file__).parents[1] / 'dizquetv/native_probe.py')
base = importlib.util.module_from_spec(spec)
spec.loader.exec_module(base)


class Native(base.Native):
    def observe(self, action, *arguments):
        return json.loads(self.command(action, 'node', '/opt/module-target-nodejs/inspect.js', action, *arguments))

    @staticmethod
    def message(stream):
        lines = []
        for _ in range(40):
            line = stream.readline(8192)
            if not line:
                raise EOFError('Debugger closed before a complete header')
            lines.append(line)
            if line == b'\r\n':
                break
        else:
            raise ValueError('Debugger header exceeded bound')
        headers = BytesHeaderParser().parsebytes(b''.join(lines))
        size = int(headers['Content-Length'])
        assert 0 <= size <= 2 * 1024 * 1024
        data = stream.read(size)
        assert len(data) == size
        return dict(headers=dict(headers), body=None if not data else json.loads(data))

    def evaluate(self, expression):
        endpoint = self.runtime['endpoints']['target']
        with socket.create_connection((endpoint['host'], endpoint['port']), 5) as peer:
            peer.settimeout(5)
            with peer.makefile('rb') as stream:
                handshake = self.message(stream)
                body = json.dumps(dict(seq=1, type='request', command='evaluate', arguments={'expression': expression, 'global': True})).encode()
                peer.sendall(('Content-Length: %d\r\n\r\n' % len(body)).encode() + body)
                events = []
                for _ in range(16):
                    result = self.message(stream)
                    events.append(result)
                    if (result['body'] or {}).get('request_seq') == 1:
                        row = dict(expression=expression, handshake=handshake, events=events, response=result['body'])
                        self.journal.setdefault('debugger', []).append(row)
                        self.save()
                        return row
                raise ValueError('No matching debugger response within the event bound')

    def ready(self, callback_port):
        metadata = self.observe('metadata')
        assert metadata['version'] == 'v7.10.1' and metadata['uid'] == 1000
        baseline = self.observe('state', callback_port)
        assert len(baseline['processes']) == 1 and baseline['connections'] == []
        version = self.evaluate('process.version')
        assert version['handshake']['headers']['Protocol-Version'] == '1'
        assert version['handshake']['headers']['V8-Version']
        assert version['response']['success'] is True and version['response']['body']['value'] == 'v7.10.1'
        controls = []
        for label, marker in [('plain', b'node-native'), ('rich', "Node 'quote' \u2603\r\nsecond line".encode())]:
            path = '/tmp/module-target-nodejs-native-' + label
            assert self.observe('file', path) == dict(exists=False)
            expression = "process.mainModule.require('fs').writeFileSync(%s,Buffer.from(%s,'base64'));process.getuid()" % (json.dumps(path), json.dumps(base64.b64encode(marker).decode()))
            try:
                reply = self.evaluate(expression)
                assert reply['response']['success'] is True and reply['response']['body']['value'] == 1000
                proof = self.observe('file', path)
                assert proof['uid'] == 1000 and proof['base64'] == base64.b64encode(marker).decode()
                controls.append(dict(label=label, proof=proof))
            finally:
                assert self.observe('file', path, 'remove') == dict(exists=False)
        negative = self.evaluate("(function(){throw Error('native-negative')})()")
        assert negative['response']['success'] is False
        after = self.observe('state', callback_port)
        for state in [after, baseline]:
            for process in state['processes']:
                process.pop('state')
        assert after == baseline
        return dict(passed=True, module_invoked=False, metadata=metadata, baseline=baseline, controls=controls, negative=negative)


if __name__ == '__main__':
    runtime = json.loads(Path(os.environ['MODULE_TARGET_RUNTIME']).read_text())
    directory = tempfile.mkdtemp(prefix='node-native-', dir=runtime['artifacts'])
    native = Native(runtime, directory)
    action = sys.argv[1]
    if action == 'before':
        result = native.ready(sys.argv[2])
    elif action in ['state', 'file', 'process']:
        result = native.observe(action, *sys.argv[2:])
    else:
        raise ValueError('Unknown native action')
    print(json.dumps(result))
