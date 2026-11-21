"""Real redis-cli/Lua controls and stock-image process/file observations."""

from pathlib import Path
import base64
import csv
import importlib.util
import io
import json
import os
import re
import shlex
import sys
import tempfile

spec = importlib.util.spec_from_file_location('native_base', Path(__file__).parents[1] / 'dizquetv/native_probe.py')
base = importlib.util.module_from_spec(spec)
spec.loader.exec_module(base)

PASSWORD = 'module-target-redis-password'
LIBRARY = '/usr/lib/x86_64-linux-gnu/liblua5.1.so.0'
CONFIGURED_PASSWORD = object()


class Native(base.Native):
    def __init__(self, runtime, directory):
        super().__init__(runtime, directory)
        family = Path(runtime['artifacts']).name
        assert family in ['redis_lua', 'redis_lua_open', 'redis_lua_fixed', 'redis_protocol_utf8', 'redis_protocol_ascii']
        self.settings = json.loads((Path('test/module_targets') / family / 'settings.json').read_text())

    def cli(self, *arguments, password=CONFIGURED_PASSWORD, stdin=None):
        if password is CONFIGURED_PASSWORD:
            password = self.settings.get('password', PASSWORD)
        argv = ['redis-cli', '--raw', '--no-auth-warning']
        if password is not None:
            argv += ['-a', password]
        return self.command('redis-cli', *argv, *arguments, stdin=stdin)

    def file(self, path, remove=False):
        assert re.fullmatch(r'/tmp/module-target-redis-[a-zA-Z0-9_-]+', path), path
        code = r'''my $path=shift; unlink($path) or die $! if shift() && -e $path;
          if (-f $path) {open my $handle,'<:raw',$path or die $!;local $/;my $bytes=<$handle>;
          close $handle;print "1\t",(stat($path))[4],"\t",unpack('H*',$bytes),"\n";}else{print "0\n";}'''
        fields = next(csv.reader(io.StringIO(self.command('file', 'perl', '-e', code, path, '1' if remove else '0').decode()), delimiter='\t'))
        if fields == ['0']:
            return dict(exists=False)
        assert len(fields) == 3 and fields[0] == '1'
        return dict(exists=True, uid=int(fields[1]), base64=base64.b64encode(bytes.fromhex(fields[2])).decode())

    def state(self, callback_port):
        # Perl core is present in the stock images; no JSON module is needed.
        # Observe every UID101 process, including shells reparented to docker-init.
        assert 1 <= int(callback_port) <= 65535
        code = r'''my $port=sprintf('%04X',shift);for my $directory (glob('/proc/[0-9]*')) {
          my ($pid)=$directory=~m{/([0-9]+)$};next if $pid == $$;
          open my $status,'<',"$directory/status" or next;local $/;my $details=<$status>;close $status;
          my ($uid)=$details=~/^Uid:\s+(\d+)/m;next unless defined($uid) && $uid==101;
          open my $stat,'<',"$directory/stat" or next;my $raw=<$stat>;close $stat;$raw=~s/^.*\) //s;
          my @fields=split(/\s+/,$raw);open my $command,'<:raw',"$directory/cmdline" or next;
          my $bytes=<$command>;close $command;
          next if $bytes=~/^(?:\/bin\/)?sh\x00-c\x00redis-cli --no-auth-warning -a / || $bytes=~/^(?:redis-cli\x00--no-auth-warning\x00-a\x00[^\x00]*\x00PING\x00|grep\x00-qx\x00PONG\x00)$/;
          print join("\t",'process',$pid,$fields[1],$fields[19],$uid,$fields[0],unpack('H*',$bytes)),"\n";
        }
        for my $name ('tcp','tcp6') {open my $sockets,'<',"/proc/net/$name" or die $!;
          local $/="\n";<$sockets>;while(my $line=<$sockets>) {my @fields=split(/\s+/,$line=~s/^\s+//r);
          next unless $fields[2]=~/:$port$/ && $fields[3] ne '06' && $fields[9] ne '0';
          print join("\t",'socket',$name,@fields[1,2,3,7,9]),"\n";}close $sockets;
        }'''
        rows = csv.reader(io.StringIO(self.command('process-state', 'perl', '-e', code, str(callback_port)).decode()), delimiter='\t')
        processes, connections = [], []
        for row in rows:
            if row[0] == 'process':
                processes.append(dict(pid=int(row[1]), ppid=int(row[2]), birth=row[3], uid=int(row[4]),
                                      state=row[5], command=bytes.fromhex(row[6]).replace(b'\0', b' ').decode().strip()))
            else:
                assert row[0] == 'socket' and len(row) == 7, row
                connections.append(dict(family=row[1], local=row[2], remote=row[3], state=row[4], uid=int(row[5]), inode=row[6]))
        return dict(processes=sorted(processes, key=lambda row: row['pid']), connections=connections)

    def snapshot(self):
        config = self.cli('CONFIG', 'GET', '*').decode().splitlines()
        assert len(config) % 2 == 0
        values = dict(zip(config[::2], config[1::2]))
        assert values['dir'] == '/tmp' and values['appendonly'] == 'no' and values['save'] == ''
        assert values['requirepass'] == (self.settings.get('password', PASSWORD) if self.settings['authenticated'] else '')
        databases = {}
        for database in ['0', '2']:
            keys = self.cli('-n', database, 'KEYS', '*').decode().splitlines()
            databases[database] = {key: self.cli('-n', database, 'DUMP', key).hex() for key in sorted(keys) if key}
        return dict(config=values, databases=databases, foreign=self.file('/tmp/module-target-redis-foreign'))

    def evaluate(self, command, path, expected):
        assert ']=]' not in command
        script = 'local loader=package.loadlib(ARGV[1],"luaopen_os");local os=loader();return os.execute(ARGV[2])'
        response = self.cli('EVAL', script, '0', LIBRARY, command)
        proof = self.file(path)
        if self.settings['vulnerable']:
            assert response == b'0\n' and proof == dict(exists=True, uid=101, base64=base64.b64encode(expected).decode()), (response, proof)
        else:
            assert b"nonexistent global variable 'package'" in response and proof == dict(exists=False), (response, proof)
        return dict(response_base64=base64.b64encode(response).decode(), proof=proof)

    def control(self, command, path, expected):
        before = self.snapshot()
        assert self.file(path) == dict(exists=False)
        try:
            self.command('same-command-cli', 'sh', '-c', command)
            assert self.file(path) == dict(exists=True, uid=101, base64=base64.b64encode(expected).decode())
            self.file(path, True)
            lua = self.evaluate(command, path, expected)
        finally:
            self.file(path, True)
        assert self.snapshot() == before
        return dict(passed=True, command_base64=base64.b64encode(command.encode()).decode(), lua=lua)

    def ready(self, callback_port):
        package = self.command('packages', 'dpkg-query', '-W', '-f=${Package}\t${Version}\n', 'redis-server', 'redis-tools', 'liblua5.1-0').decode()
        assert 'redis-server\t' + self.settings['package'] + '\n' in package
        hashes = self.command('binaries', 'sha256sum', '/usr/bin/redis-server', LIBRARY).decode()
        assert hashes.split()[0] == self.settings['binary_sha256']
        assert '9e254c93064b940a87b1917ec97f89fb8e5941bdff509d3ed14b9410b5af1b38' in hashes
        info = self.cli('INFO', 'server').decode()
        assert 'redis_version:' + self.settings['version'] + '\r\n' in info
        assert self.cli('PING') == b'PONG\n'
        noauth = self.cli('PING', password=None)
        wrong = self.cli('PING', password='wrong-password')
        if self.settings['authenticated']:
            assert b'NOAUTH' in noauth and b'NOAUTH' in wrong
        else:
            assert noauth == b'PONG\n' and wrong == b'PONG\n'
        assert self.cli('EVAL', 'return 21*2', '0') == b'42\n'
        assert b'Error compiling script' in self.cli('EVAL', 'this is not Lua', '0')
        for database in ['0', '2']:
            assert self.cli('-n', database, 'DBSIZE') == b'0\n'
            assert self.cli('-n', database, 'SET', 'module-target-sentinel', 'preserve-' + database) == b'OK\n'
            assert self.cli('-n', database, 'RPUSH', 'module-target-list', 'alpha', 'beta') == b'2\n'
        baseline = self.snapshot()
        controls = []
        for label, marker in [('plain', b'redis-native'), ('rich', 'Redis \'quote\' "double" \\slash \u2603\r\nsecond line'.encode())]:
            path = '/tmp/module-target-redis-native-' + label
            command = 'printf %s ' + shlex.quote(marker.decode()) + ' > ' + path
            controls.append(self.control(command, path, marker))
        assert self.snapshot() == baseline
        state = self.state(callback_port)
        assert state['connections'] == [] and len(state['processes']) == 2, state
        assert len([row for row in state['processes'] if row['command'].startswith('redis-server ')]) == 1
        return dict(passed=True, module_invoked=False, settings=self.settings, library=LIBRARY, packages=package, hashes=hashes,
                    baseline=baseline, state=state, controls=controls)


if __name__ == '__main__':
    runtime = json.loads(Path(os.environ['MODULE_TARGET_RUNTIME']).read_text())
    native = Native(runtime, tempfile.mkdtemp(prefix='redis-lua-native-', dir=runtime['artifacts']))
    action, *arguments = sys.argv[1:]
    if action == 'before':
        result = native.ready(arguments[0])
    elif action == 'snapshot':
        result = native.snapshot()
    elif action == 'state':
        result = native.state(arguments[0])
    elif action == 'file':
        result = native.file(arguments[0], len(arguments) > 1 and arguments[1] == 'remove')
    elif action == 'command-control':
        result = native.control(base64.b64decode(arguments[0]).decode(), arguments[1], base64.b64decode(arguments[2]))
    else:
        raise ValueError('Unknown native action')
    print(json.dumps(result))
