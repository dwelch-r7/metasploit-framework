"""Replay only task-owned recovered credentials against local genuine services."""
import base64
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import urllib.error
import urllib.request


kind, source = sys.argv[1:]
assert kind in ('ssh', 'docker', 'gem')
source_path = Path(source).resolve(strict=True)
assert source_path.parent == Path('/opt/module-target-artifacts')
credential = json.loads(source_path.read_text())
records = []
success = False


def run(arguments, **options):
    result = subprocess.run(arguments, capture_output=True, timeout=25, **options)
    records.append(dict(argv=arguments, stdout=result.stdout.decode(errors='replace'),
                        stderr=result.stderr.decode(errors='replace'), exitstatus=result.returncode))
    assert result.returncode == 0, records[-1]


try:
    if kind == 'ssh':
        private = source_path.with_suffix('.pem')
        run(['ssh', '-n', '-F', '/dev/null', '-i', str(private), '-l', credential['username'],
             '-o', 'IdentitiesOnly=yes', '-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=no',
             '-o', 'UserKnownHostsFile=/dev/null', '-o', 'ConnectTimeout=3', '127.0.0.1', 'id -un'])
        assert records[-1]['stdout'].strip() == credential['username']
    elif kind == 'docker':
        assert credential['realm_value'] == '127.0.0.1:5000'
        request = urllib.request.Request('http://127.0.0.1:5000/v2/')
        value = credential['username'] + ':' + credential['private_data']
        request.add_header('Authorization', 'Basic ' + base64.b64encode(value.encode()).decode())
        try:
            response = urllib.request.urlopen(request, timeout=5)
        except urllib.error.HTTPError as error:
            response = error
        records.append(dict(status=response.code, headers=dict(response.headers),
                            body=response.read().decode()))
        assert response.code == 200
    else:
        version = '1.0.' + str(time.time_ns())
        directory = Path('/opt/credential-state/gem-proof')
        spec = directory / 'module-target-credential-proof.gemspec'
        spec.write_text('Gem::Specification.new do |spec|\n'
                        f'spec.name="module-target-credential-proof";spec.version="{version}";'
                        'spec.authors=["Module Target"];spec.summary="Owned local credential proof";'
                        'spec.files=["proof.rb"];spec.license="MIT"\nend\n')
        run(['gem', 'build', spec.name], cwd=directory)
        gem = directory / f'module-target-credential-proof-{version}.gem'
        environment = dict(os.environ, GEM_HOST_API_KEY=credential['private_data'],
                           RUBYGEMS_HOST='http://127.0.0.1:9292/private')
        pushed = False
        try:
            run(['gem', 'push', str(gem), '--host', 'http://127.0.0.1:9292/private'], env=environment)
            pushed = True
            request = urllib.request.Request(f'http://127.0.0.1:9292/private/gems/{gem.name}')
            request.add_header('Authorization', 'Basic ' + base64.b64encode((credential['private_data'] + ':').encode()).decode())
            response = urllib.request.urlopen(request, timeout=5)
            assert response.read() == gem.read_bytes()
            records.append(dict(status=response.code, bytes=gem.stat().st_size, exact_package_bytes=True))
        finally:
            if pushed:
                run(['gem', 'yank', 'module-target-credential-proof', '--version', version], env=environment)
            gem.unlink(missing_ok=True)
    success = True
except (AssertionError, OSError, ValueError, urllib.error.URLError) as error:
    records.append(dict(error_class=type(error).__name__, error=str(error)))
print(json.dumps(dict(kind=kind, success=success, records=records)))
