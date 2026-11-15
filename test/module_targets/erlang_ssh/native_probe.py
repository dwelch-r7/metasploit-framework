"""Vendor identity, authentication, and independent preauthentication controls."""
import base64
import json
import shlex
from pathlib import Path
import subprocess
import sys
import time
import uuid

from ssh_wire import probe


def main():
    runtime = json.loads(Path(sys.argv[1]).read_text())
    profile = json.loads((Path(__file__).parent / 'profiles.json').read_text())[sys.argv[2]]
    release = json.loads((Path(__file__).parent / 'releases.json').read_text())[profile['version']]
    commands = []

    def execute(*arguments):
        result = subprocess.run(runtime['compose'] + ['exec', '-T', 'target', *arguments],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=25, check=False)
        row = {'argv': arguments, 'exit': result.returncode,
               'stdout': result.stdout.decode(errors='replace'), 'stderr': result.stderr.decode(errors='replace')}
        commands.append(row)
        assert result.returncode == 0, row
        return row['stdout']

    report = {'phase': sys.argv[3], 'profile': sys.argv[2], 'commands': commands,
              'probes': [], 'module_calls': 0, 'qualification_claim': False}
    try:
        identity = json.loads(execute('escript', '/opt/module-target/native.escript', 'inspect'))
        report['identity'] = identity
        assert identity['otp'] == profile['version'] and identity['ssh'] == release['ssh_version']
        assert identity['uid'] == profile['uid'] and identity['architecture'].startswith('x86_64-')
        assert identity['beam_sha256'] == release['beam_sha256']
        account = execute('getent', 'passwd', str(profile['uid'])).strip().split(':')
        assert len(account) == 7 and int(account[2]) == int(account[3]) == profile['uid']
        report['os_account'] = {'name': account[0], 'uid': int(account[2]), 'gid': int(account[3]), 'home': account[5], 'shell': account[6]}
        for password, accepted in [('module-target-wrong-password', False), ('module-target-erlang-password', True)]:
            output = execute('escript', '/opt/module-target/native.escript', 'auth', password)
            assert ('AUTHENTICATED=true' in output) == accepted
            assert ('AUTHENTICATED=false' in output) != accepted
            if accepted:
                assert 'module_target_authenticated' in output
        endpoint = runtime['endpoints']['target']
        for kind in ['simple', 'quoted', 'unicode']:
            nonce = 'native_' + uuid.uuid4().hex
            path = '/tmp/module-target-erlang/' + nonce
            execute('test', '!', '-e', path)
            marker = nonce + '_café_☃_🚀_e\u0301' if kind == 'unicode' else nonce
            command = ('printf %s ' if kind == 'simple' else 'printf "%s" ') + shlex.quote(marker) + ' > ' + path
            observed = probe(endpoint['host'], endpoint['port'], command,
                             response_timeout=0.25 if profile['affected'] else 4)
            report['probes'].append({'kind': kind, 'command': command, 'nonce': nonce, 'expected_bytes_base64': base64.b64encode(marker.encode()).decode(), 'path': path, 'wire': observed})
            assert 'error' not in observed and observed['execution_sent'], observed
            if profile['affected']:
                deadline = time.monotonic() + 3
                while True:
                    actual = execute('sh', '-c', 'if test -f "$1";then cat "$1";fi', 'sh', path)
                    if actual or time.monotonic() >= deadline:
                        assert actual == marker
                        break
                    time.sleep(0.05)
                assert execute('stat', '-c', '%u', path).strip() == str(profile['uid'])
                execute('rm', '--', path)
            else:
                assert observed.get('read_end') == 'EOFError' or observed['verdict'] == 'preauth_channel_rejected'
            execute('test', '!', '-e', path)
        output = execute('escript', '/opt/module-target/native.escript', 'auth', 'module-target-erlang-password')
        assert 'AUTHENTICATED=true' in output and 'module_target_authenticated' in output
        assert json.loads(execute('escript', '/opt/module-target/native.escript', 'inspect')) == identity
        report['status'] = 'passed'
        return 0
    except (AssertionError, OSError, ValueError, subprocess.SubprocessError) as error:
        report.update(status='setup_failed', error={'class': type(error).__name__, 'message': str(error)})
        return 1
    finally:
        print(json.dumps(report))


if __name__ == '__main__':
    raise SystemExit(main())
