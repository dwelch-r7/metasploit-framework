from pathlib import Path
import base64
import hashlib
import json
import os
import subprocess
import tempfile

fixtures = Path('/opt/netrc-fixtures')
expected = Path('/opt/protected-source.html').read_bytes()
observations = []

def request(label, fixture=None, host='netrc-auth', expected_status=200, connect_to=None):
    with tempfile.TemporaryDirectory(prefix='native-netrc-') as directory:
        body = Path(directory) / 'body'
        args = ['curl', '-q', '--noproxy', '*', '--silent', '--show-error', '--fail',
                '--connect-timeout', '3', '--max-time', '6', '--output', str(body), '--write-out', '%{http_code}']
        if fixture:
            args += ['--netrc-file', str(fixtures / fixture)]
        if connect_to:
            args += ['--connect-to', connect_to]
        args += ['http://' + host + '/protected/']
        result = subprocess.run(args, capture_output=True, text=True, timeout=10)
        assert result.stdout == str(expected_status), (label, result.returncode, result.stdout, result.stderr)
        if expected_status == 200:
            assert result.returncode == 0 and body.read_bytes() == expected
        else:
            assert result.returncode == 22
        observations.append({'label': label, 'argv': args, 'exit': result.returncode,
                             'http_status': int(result.stdout), 'stderr': result.stderr,
                             'body_sha256': hashlib.sha256(body.read_bytes()).hexdigest() if body.exists() else None,
                             'temporary_directory': directory})
    assert not Path(directory).exists()

request('unauthenticated', expected_status=401)
request('wrong-password', 'wrong.netrc', expected_status=401)
for name in ['multiline.netrc', 'inline.netrc', 'tabs.netrc', 'comments.netrc', 'multiple.netrc']:
    request(name, name)
request('second-machine', 'multiple.netrc', host='netrc-alias')
request('comment-does-not-provide-authentication', 'comments.netrc', host='comment.invalid',
        expected_status=401, connect_to='comment.invalid:80:netrc-auth:80')

files = {}
for path in sorted(fixtures.iterdir()):
    raw = path.read_bytes()
    info = path.stat()
    files[path.name] = {'sha256': hashlib.sha256(raw).hexdigest(), 'base64': base64.b64encode(raw).decode(),
                        'mode': oct(info.st_mode & 0o777), 'uid': info.st_uid, 'gid': info.st_gid}
resources = {}
for name in ['memory.events', 'pids.events']:
    resources[name] = dict(line.split() for line in Path('/sys/fs/cgroup', name).read_text().splitlines())
assert resources['memory.events']['oom'] == resources['memory.events']['oom_kill'] == '0'
assert resources['pids.events']['max'] == '0'
packages = subprocess.check_output(['dpkg-query', '-W', '-f=${Package}=${Version}\n', 'curl', 'python3'], text=True)
assert 'curl=7.81.0-1ubuntu1.30\n' in packages and 'python3=3.10.6-1~22.04.1\n' in packages
print(json.dumps({'uid': os.geteuid(), 'hostname': subprocess.check_output(['hostname'], text=True).strip(),
                  'curl_version': subprocess.check_output(['curl', '--version'], text=True),
                  'packages': packages,
                  'fixtures': files, 'controls': observations, 'resources': resources,
                  'native_passed': True, 'owner_calls': 0}, indent=2))
