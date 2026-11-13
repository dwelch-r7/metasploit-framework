"""Build unchanged libssh stacks and source-available vendor example applications."""
from pathlib import Path
import hashlib
import json
import os
import shutil
import subprocess
import tarfile

catalog = json.loads(Path('/lab-source/releases.json').read_text())
output = Path('/lab-output')
output.mkdir()
records = {}


def run(argv, **options):
    subprocess.run(argv, check=True, **options)


for version, release in catalog.items():
    archive = Path('/archives') / ('libssh-' + version + '.tar.xz')
    assert hashlib.sha256(archive.read_bytes()).hexdigest() == release['sha256']
    source = Path('/source') / ('libssh-' + version)
    source.parent.mkdir(exist_ok=True)
    with tarfile.open(archive, 'r:xz') as compressed:
        compressed.extractall(source.parent, filter='data')
    original = source / 'examples/ssh_server_fork.c'
    stock = original.read_text()
    # Configure banners through the public libssh API. The lifetime guard makes
    # disconnected clients leave the example's callback-dispatch loop promptly.
    anchor = next(line for line in stock.splitlines(keepends=True) if 'ssh_bind_listen(sshbind)' in line)
    assert stock.count(anchor) == 1
    hook = '    {\n        const char *banner = getenv("LIBSSH_LAB_BANNER");\n        if (banner != NULL) { ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_BANNER, banner); }\n    }\n\n'
    stock = stock.replace(anchor, hook + anchor)
    guarded = 'while (sdata.authenticated == 0 || sdata.channel == NULL) {'
    assert guarded in stock
    stock = stock.replace(guarded, 'while ((sdata.authenticated == 0 || sdata.channel == NULL) && ssh_is_connected(session)) {')
    stock = stock.replace('    ssh_set_channel_callbacks(sdata.channel, &channel_cb);', '    if (sdata.authenticated == 0 || sdata.channel == NULL) { return; }\n    ssh_set_channel_callbacks(sdata.channel, &channel_cb);')
    original.write_text(stock)
    prefix = output / version
    build = Path('/build') / version
    run(['cmake', '-S', str(source), '-B', str(build), '-DCMAKE_BUILD_TYPE=Release', '-DCMAKE_C_FLAGS=-fcommon', '-DCMAKE_INSTALL_PREFIX=' + str(prefix), '-DCMAKE_INSTALL_LIBDIR=lib', '-DCMAKE_INSTALL_RPATH=/opt/libssh/' + version + '/lib', '-DCMAKE_BUILD_WITH_INSTALL_RPATH=ON', '-DWITH_GCRYPT=ON', '-DWITH_GSSAPI=OFF', '-DWITH_SFTP=OFF', '-DWITH_STATIC_LIB=OFF', '-DWITH_EXAMPLES=ON', '-DUNIT_TESTING=OFF'])
    run(['cmake', '--build', str(build), '--parallel', '2'])
    run(['cmake', '--install', str(build)])
    shutil.copy2(build / 'examples/ssh_server_fork', prefix / 'server-guarded')
    # Apply the Framework guide's existing callback/shell patch to the untouched
    # example, then reapply the identical banner/lifetime configuration.
    original.write_text(tarfile.open(archive, 'r:xz').extractfile('libssh-' + version + '/examples/ssh_server_fork.c').read().decode())
    run(['patch', str(original), '/lab-source/ssh_server_fork.patch'])
    patched = original.read_text().replace(anchor, hook + anchor)
    patched = patched.replace('while (sdata.channel == NULL) {', 'while (sdata.channel == NULL && ssh_is_connected(session)) {')
    patched = patched.replace('    ssh_set_channel_callbacks(sdata.channel, &channel_cb);', '    if (sdata.channel == NULL) { return; }\n    ssh_set_channel_callbacks(sdata.channel, &channel_cb);')
    original.write_text(patched)
    run(['cmake', '--build', str(build), '--parallel', '2', '--target', 'ssh_server_fork'])
    shutil.copy2(build / 'examples/ssh_server_fork', prefix / 'server-open')
    run(['cc', '/lab-source/version.c', '-I' + str(prefix / 'include'), '-L' + str(prefix / 'lib'), '-Wl,-rpath,/opt/libssh/' + version + '/lib', '-lssh', '-o', str(prefix / 'version')])
    libraries = [path for path in (prefix / 'lib').glob('libssh.so.*') if not path.is_symlink()]
    assert len(libraries) == 1
    records[version] = {'release': release, 'stock_example_sha256': hashlib.sha256(stock.encode()).hexdigest(), 'open_example_sha256': hashlib.sha256(patched.encode()).hexdigest(), 'library': '/opt/libssh/' + str(libraries[0].relative_to(output)), 'library_sha256': hashlib.sha256(libraries[0].read_bytes()).hexdigest()}
    shutil.copy2(original, prefix / 'server-open.c')
    (prefix / 'server-guarded.c').write_text(stock)
    for folder in ['include', 'lib/cmake', 'lib/pkgconfig']:
        shutil.rmtree(prefix / folder, ignore_errors=True)
binaries = [path for path in sorted(output.rglob('*')) if path.is_file() and not path.is_symlink() and (path.name in ['server-open', 'server-guarded', 'version'] or path.name.startswith('libssh.so.'))]
(output / 'binaries.sha256').write_text(''.join(hashlib.sha256(path.read_bytes()).hexdigest() + '  ' + str(path.relative_to(output)) + '\n' for path in binaries))
(output / 'build.json').write_text(json.dumps(records, indent=2) + '\n')
