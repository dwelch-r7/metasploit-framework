"""Build release-tag OpenSSL sources without changing the heartbeat implementation."""
from pathlib import Path
import hashlib
import json
import shutil
import subprocess
import tarfile

releases = json.loads(Path('/lab-source/releases.json').read_text())
records = {}
variants = [(version, version, []) for version in releases]
variants.append(('1.0.1f-no-heartbeats', '1.0.1f', ['-DOPENSSL_NO_HEARTBEATS']))
for name, version, extra in variants:
    release = releases[version]
    archive = Path('/archives') / (version + '.tar.gz')
    assert hashlib.sha256(archive.read_bytes()).hexdigest() == release['sha256']
    folder = Path('/source') / name
    folder.mkdir(parents=True)
    with tarfile.open(archive, 'r:gz') as compressed:
        compressed.extractall(folder, filter='data')
    source = next(folder.iterdir())
    prefix = '/opt/openssl/' + name
    arguments = ['./config', 'no-shared', 'no-asm', 'no-ssl2', '-fcommon', '--prefix=' + prefix, '--openssldir=' + prefix + '/ssl', *extra]
    subprocess.run(arguments, cwd=source, check=True)
    subprocess.run(['make', 'depend'], cwd=source, check=True)
    subprocess.run(['make', '-j2', 'build_libs'], cwd=source, check=True)
    subprocess.run(['make', '-j2', 'build_apps'], cwd=source, check=True)
    subprocess.run(['make', 'openssl.pc', 'libssl.pc', 'libcrypto.pc'], cwd=source, check=True)
    subprocess.run(['make', 'install_sw', 'INSTALL_PREFIX=/output'], cwd=source, check=True)
    installed = Path('/output' + prefix)
    shutil.copy2(source / 'LICENSE', installed / 'LICENSE')
    records[name] = {'release': release, 'configure': arguments, 'heartbeat_disabled': bool(extra), 'openssl_sha256': hashlib.sha256((installed / 'bin/openssl').read_bytes()).hexdigest()}
    shutil.rmtree(folder)
output = Path('/output/opt/openssl')
(output / 'build.json').write_text(json.dumps(records, indent=2) + '\n')
files = [path for path in sorted(output.rglob('*')) if path.is_file() and not path.is_symlink() and path.name in ['openssl', 'libssl.a', 'libcrypto.a']]
assert len(files) == 12
(output / 'binaries.sha256').write_text(''.join(hashlib.sha256(path.read_bytes()).hexdigest() + '  ' + str(path.relative_to(output)) + '\n' for path in files))
