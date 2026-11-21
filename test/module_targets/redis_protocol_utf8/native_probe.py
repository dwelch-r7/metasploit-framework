"""Real Redis data, authentication and stock CLI request captures."""

from pathlib import Path
import base64
import importlib.util
import json
import os
import socket
import threading
import select
import tempfile
import sys

spec = importlib.util.spec_from_file_location('redis_native', Path(__file__).parents[1] / 'redis_lua/native_probe.py')
redis_native = importlib.util.module_from_spec(spec)
spec.loader.exec_module(redis_native)

UPLOAD = "\nupload '雪'\x00payload\n".encode()


def normalized(value):
    if isinstance(value, str):
        return dict(kind='string', base64=base64.b64encode(value.encode()).decode())
    if isinstance(value, list):
        return dict(kind='array', values=[normalized(item) for item in value])
    if isinstance(value, dict):
        return dict(kind='hash', pairs=sorted([[normalized(key), normalized(item)] for key, item in value.items()], key=lambda row: row[0]['base64']))
    raise TypeError(type(value))


class Native(redis_native.Native):
    def file(self, path, remove=False):
        # Accept only this fixture's flat /tmp names, including its Unicode RDB.
        assert path.startswith('/tmp/module-target-redis-') and '/' not in path[5:] and '\0' not in path
        code = r'''my $path=shift;unlink($path) or die $! if shift() && -e $path;
          if (-f $path) {open my $file,'<:raw',$path or die $!;local $/;my $data=<$file>;close $file;
          my $uid=(stat($path))[4];print $uid,"\t",unpack('H*',$data),"\n";}else{print "missing\n";}'''
        raw = self.command('physical-file', 'perl', '-e', code, path, '1' if remove else '0').decode().rstrip('\n')
        if raw == 'missing':
            return dict(exists=False)
        uid, data = raw.split('\t')
        return dict(exists=True, uid=int(uid), base64=base64.b64encode(bytes.fromhex(data)).decode())

    def data(self):
        values = {}
        for key in ['clé☃', 'empty', 'tail', 'liste☃', 'ensemble', 'scores', 'haché']:
            kind = self.cli('TYPE', key).decode().strip()
            commands = {'string': 'GET', 'list': 'LRANGE', 'set': 'SMEMBERS', 'zset': 'ZRANGE', 'hash': 'HGETALL'}
            arguments = ',0,-1' if kind == 'list' else ',0,-1' if kind == 'zset' else ''
            script = 'return cjson.encode(redis.call("' + commands[kind] + '",KEYS[1]' + arguments + '))'
            value = json.loads(self.cli('EVAL', script, '1', key))
            if kind == 'hash':
                value = dict(zip(value[::2], value[1::2]))
            values[base64.b64encode(key.encode()).decode()] = normalized(value)
        return values

    def upload_control(self, path):
        before = self.snapshot()
        assert self.file(path) == dict(exists=False)
        key = 'module-target-native-upload'
        try:
            assert self.cli('CONFIG', 'SET', 'dbfilename', Path(path).name) == b'OK\n'
            assert self.cli('CONFIG', 'SET', 'rdbcompression', 'no') == b'OK\n'
            assert self.cli('-x', 'SETNX', key, stdin=UPLOAD) == b'1\n'
            assert self.cli('SAVE') == b'OK\n'
            proof = self.file(path)
            raw = base64.b64decode(proof['base64'])
            assert proof['uid'] == 101 and raw.startswith(b'REDIS') and UPLOAD in raw
        finally:
            for name in ['dbfilename', 'rdbcompression']:
                assert self.cli('CONFIG', 'SET', name, before['config'][name]) == b'OK\n'
            assert self.cli('DEL', key) == b'1\n'
            self.file(path, True)
        assert self.snapshot() == before
        return dict(passed=True, payload_base64=base64.b64encode(UPLOAD).decode(), proof=proof)

    def wire_capture(self, username=None):
        # A raw collector captures stock redis-cli requests for unit fixtures.
        # Its canned ACKs are never used for module or real-service verdicts.
        server = socket.socket()
        server.bind(('0.0.0.0', 0))
        server.listen(1)
        server.settimeout(8)
        packets, errors = [], []

        def collect():
            try:
                with server.accept()[0] as peer:
                    peer.settimeout(5)
                    for _ in range(2):
                        chunks = [peer.recv(65536)]
                        while select.select([peer], [], [], 0.1)[0]:
                            part = peer.recv(65536)
                            if not part:
                                break
                            chunks.append(part)
                        packets.append(base64.b64encode(b''.join(chunks)).decode())
                        peer.sendall(b'+OK\r\n' if len(packets) == 1 else b'+PONG\r\n')
            except BaseException as error:
                errors.append(repr(error))

        thread = threading.Thread(target=collect)
        thread.start()
        try:
            user_options = [] if username is None else ['--user', username]
            reply = self.cli(*user_options, '-h', 'host.docker.internal', '-p', str(server.getsockname()[1]), 'PING')
            thread.join(8)
            assert not thread.is_alive() and not errors and reply == b'PONG\n' and len(packets) == 2, (errors, reply)
            return dict(producer='stock redis-cli 6.0.11', fixture_only=True, password=self.settings['password'], username=username, packets_base64=packets)
        finally:
            server.close()
            thread.join(8)

    def ready(self, port):
        result = super().ready(port)
        assert result['baseline']['config']['dbfilename'] == 'dump.rdb'
        self.command('default-snapshot-originally-absent', 'test', '!', '-e', '/tmp/dump.rdb')
        seeds = [
            (['-x', 'SET', 'clé☃'], "value '雪'\0\r\nline".encode(), b'OK\n'),
            (['-x', 'SET', 'empty'], b'', b'OK\n'),
            (['-x', 'SET', 'tail'], b'leading and trailing \r\n\t ', b'OK\n'),
            (['RPUSH', 'liste☃', 'été', 'next\r\nline'], None, b'2\n'),
            (['SADD', 'ensemble', 'été'], None, b'1\n'),
            (['ZADD', 'scores', '1', '雪'], None, b'1\n'),
            (['HSET', 'haché', 'champ☃', '', 'other', 'é'], None, b'2\n')
        ]
        for arguments, stdin, expected in seeds:
            assert self.cli(*arguments, stdin=stdin) == expected
        assert self.cli('GET', 'empty') == b'\n' and self.cli('EXISTS', 'empty') == b'1\n'
        assert self.cli('GET', 'tail') == b'leading and trailing \r\n\t \n'
        result['values'] = self.data()
        result['wire_capture'] = self.wire_capture()
        result['upload_control'] = self.upload_control('/tmp/module-target-redis-native-☃.rdb')
        result['baseline'] = self.snapshot()
        return result


if __name__ == '__main__':
    runtime = json.loads(Path(os.environ['MODULE_TARGET_RUNTIME']).read_text())
    native = Native(runtime, tempfile.mkdtemp(prefix='redis-protocol-native-', dir=runtime['artifacts']))
    action, *arguments = sys.argv[1:]
    if action == 'before':
        result = native.ready(arguments[0])
    elif action == 'data':
        result = native.data()
    elif action == 'file':
        result = native.file(arguments[0], len(arguments) > 1 and arguments[1] == 'remove')
    elif action == 'remove-default-rdb':
        native.command('remove-owned-cleaned-snapshot', 'rm', '-f', '--', '/tmp/dump.rdb')
        result = dict(removed=True)
    elif action == 'snapshot':
        result = native.snapshot()
    elif action == 'state':
        result = native.state(arguments[0])
    else:
        raise ValueError(action)
    print(json.dumps(result))
