"""Independent stock-image HTTP, diskdb and physical-file observations."""

from pathlib import Path
import base64
import copy
import csv
import datetime
import http.client
import io
import json
import os
import re
import shlex
import subprocess
import sys


class Native:
    def __init__(self, runtime, directory):
        self.runtime = runtime
        self.directory = Path(directory)
        self.directory.mkdir(parents=True, exist_ok=True)
        self.journal = dict(commands=[], http=[])

    def save(self):
        (self.directory / 'journal.json').write_text(json.dumps(self.journal, indent=2) + '\n')

    def command(self, label, *arguments, stdin=None):
        argv = self.runtime['compose'] + ['exec', '-T', 'target', *arguments]
        result = subprocess.run(argv, input=stdin, capture_output=True, timeout=30)
        self.journal['commands'].append(dict(label=label, argv=argv, exit=result.returncode,
                                            stdout_base64=base64.b64encode(result.stdout).decode(),
                                            stderr=result.stderr.decode(errors='replace')))
        self.save()
        if result.returncode:
            raise RuntimeError(label + ': ' + result.stderr.decode(errors='replace'))
        return result.stdout

    def request(self, method, path, data=None):
        endpoint = self.runtime['endpoints']['target']
        client = http.client.HTTPConnection(endpoint['host'], endpoint['port'], timeout=10)
        body = None if data is None else json.dumps(data, ensure_ascii=False).encode()
        headers = {} if body is None else {'Content-Type': 'application/json; charset=utf-8'}
        try:
            client.request(method, path, body=body, headers=headers)
            response = client.getresponse()
            raw = response.read()
            result = dict(status=response.status, body_base64=base64.b64encode(raw).decode())
            try:
                result['json'] = json.loads(raw)
            except (json.JSONDecodeError, UnicodeDecodeError):
                pass
            self.journal['http'].append(dict(method=method, path=path, data=data, response=result))
            self.save()
            return result
        finally:
            client.close()

    def settings(self):
        response = self.request('GET', '/api/ffmpeg-settings')
        assert response['status'] == 200, response
        assert isinstance(response['json'], dict) and response['json']['_id']
        return response['json']

    def set_settings(self, data):
        return self.request('PUT', '/api/ffmpeg-settings', data)

    def databases(self):
        # The stock image has Perl core but no JSON/MIME modules. Hex encodes
        # arbitrary file bytes; csv/json on the host provide the parsers.
        code = r'''for my $path (sort glob('/home/node/app/.dizquetv/*.json')) {
          open my $handle, '<:raw', $path or die "Cannot read $path: $!";
          local $/; my $bytes=<$handle>; close $handle;
          print unpack('H*',$path),"\t",unpack('H*',$bytes),"\n";
        }'''
        raw = self.command('database-files', 'perl', '-e', code).decode()
        rows = {}
        for name, data in csv.reader(io.StringIO(raw), delimiter='\t'):
            path = bytes.fromhex(name).decode()
            rows[path] = json.loads(bytes.fromhex(data))
        assert '/home/node/app/.dizquetv/ffmpeg-settings.json' in rows
        return rows

    def snapshot(self):
        return dict(settings=self.settings(), databases=self.databases())

    def metadata(self):
        uid = int(self.command('cli-uid', 'id', '-u'))
        binary = self.command('binary-sha256', 'sha256sum', '/home/node/app/dizquetv').decode().split()[0]
        return dict(uid=uid, binary_sha256=binary)

    def file(self, path, remove=False):
        assert re.fullmatch(r'/tmp/module-target-dizquetv-[a-z0-9_-]+', path), path
        code = r'''my $path=shift; unlink($path) or die "Cannot unlink $path: $!" if shift() && -e $path;
          if (-f $path) {open my $handle,'<:raw',$path or die $!;local $/;my $bytes=<$handle>;
          close $handle;print "1\t",(stat($path))[4],"\t",unpack('H*',$bytes),"\n";}else{print "0\n";}'''
        raw = self.command('remove-proof' if remove else 'read-proof', 'perl', '-e', code, path, '1' if remove else '0').decode()
        fields = next(csv.reader(io.StringIO(raw), delimiter='\t'))
        if fields == ['0']:
            return dict(exists=False)
        assert len(fields) == 3 and fields[0] == '1'
        return dict(exists=True, uid=int(fields[1]), base64=base64.b64encode(bytes.fromhex(fields[2])).decode())

    def command_control(self, command, path, expected, vulnerable):
        baseline = self.snapshot()
        assert self.file(path) == dict(exists=False)
        direct = self.command('same-command-cli', 'sh', '-c', command)
        physical = dict(exists=True, uid=0, base64=base64.b64encode(expected).decode())
        assert direct == expected and self.file(path) == physical
        assert self.file(path, remove=True) == dict(exists=False)
        candidate = copy.deepcopy(baseline['settings'])
        # Silence the empty executable before the independent shell command.
        # Finish with a no-op so physical proof, rather than shell exit alone,
        # determines whether command execution actually happened.
        candidate['ffmpegPath'] = '" >/dev/null 2>&1; ' + command + '; : #'
        try:
            update = self.set_settings(candidate)
            if vulnerable:
                assert update['status'] == 200, update
                response = self.request('GET', '/api/version')
                assert response['status'] == 200, response
                assert response['json']['ffmpeg'].encode() == expected
                assert self.file(path) == physical
            else:
                assert update['status'] == 400, update
                assert base64.b64decode(update['body_base64']) == b'ffmpeg path must be a valid file path.'
                assert self.file(path) == dict(exists=False)
                assert self.snapshot() == baseline
                response = self.request('GET', '/api/version')
                assert response['status'] == 200 and response['json']['ffmpeg'] != 'Error'
            return dict(passed=True, vulnerable=vulnerable, command_base64=base64.b64encode(command.encode()).decode(),
                        update=update, response=response, physical=self.file(path))
        finally:
            primary = sys.exc_info()[1]
            try:
                # Fixed releases reject the write without changing state.
                # Resubmitting an unchanged record would extend the hidden
                # path-edit lock date; keep that value in the full comparison.
                if self.snapshot() != baseline:
                    assert self.set_settings(baseline['settings'])['status'] == 200
                assert self.file(path, remove=True) == dict(exists=False)
                assert self.snapshot() == baseline
            except Exception as error:
                self.journal['cleanup_error'] = dict(type=type(error).__name__, message=str(error))
                if primary is None:
                    raise


def main():
    runtime = json.loads(Path(os.environ['MODULE_TARGET_RUNTIME']).read_text())
    version = os.environ['DIZQUETV_TARGET_VERSION']
    vendor = json.loads(Path('test/module_targets/dizquetv/vendor.json').read_text())[version]
    action, *arguments = sys.argv[1:]
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%S%f').lower()
    native = Native(runtime, Path(runtime['artifacts']) / ('dizquetv-native-' + action + '-' + stamp))
    state_path = Path(runtime['artifacts']) / 'dizquetv-state.json'
    try:
        if action == 'before':
            metadata = native.metadata()
            assert metadata == dict(uid=0, binary_sha256=vendor['binary_sha256']), metadata
            response = native.request('GET', '/api/version')
            assert response['status'] == 200 and response['json']['dizquetv'] == version, response
            assert re.fullmatch(r'v12\.[0-9.]+', response['json']['nodejs']), response
            assert re.match(r'4\.3(?:\.|$)', response['json']['ffmpeg']), response
            factory = native.snapshot()
            state = dict(version=version, metadata=metadata, runtime=response['json'], factory=factory)
            state_path.write_text(json.dumps(state, indent=2) + '\n')
            if version == '1.5.3':
                candidate = copy.deepcopy(factory['settings'])
                candidate['threads'] = 2 if candidate['threads'] != 2 else 1
                assert native.set_settings(candidate)['status'] == 200
            baseline = native.snapshot()
            if version == '1.5.3':
                assert baseline['settings']['threads'] == candidate['threads']
            else:
                assert baseline == factory
            state['baseline'] = baseline
            state_path.write_text(json.dumps(state, indent=2) + '\n')
            expected = "Native 'single' \"double\" \\ 雪\r\nEnd\n".encode()
            path = '/tmp/module-target-dizquetv-native-' + str(os.getpid())
            command = 'printf %s ' + shlex.quote(expected.decode()) + ' | tee ' + path
            control = native.command_control(command, path, expected, version == '1.5.3')
            result = dict(passed=True, module_invoked=False, **state, control=control)
        elif action == 'snapshot':
            result = native.snapshot()
        elif action in ['file', 'remove']:
            result = native.file(arguments[0], remove=action == 'remove')
        elif action == 'command-control':
            command, path, expected = arguments
            result = native.command_control(base64.b64decode(command).decode(), path, base64.b64decode(expected), version == '1.5.3')
        elif action == 'after':
            state = json.loads(state_path.read_text())
            current = native.snapshot()
            preserved = current == state.get('baseline')
            if current != state['factory']:
                assert native.set_settings(state['factory']['settings'])['status'] == 200
            restored = native.snapshot() == state['factory']
            metadata = native.metadata()
            assert metadata == state['metadata']
            result = dict(preserved=preserved, restored=restored, metadata=metadata)
        else:
            raise ValueError('Unsupported native operation')
        native.journal['result'] = result
        print(json.dumps(result))
    except Exception as error:
        native.journal['error'] = dict(type=type(error).__name__, message=str(error))
        raise
    finally:
        native.save()


if __name__ == '__main__':
    main()
