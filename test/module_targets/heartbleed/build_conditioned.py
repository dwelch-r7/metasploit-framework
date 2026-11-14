"""Link the same transparent heap fixture against every recorded SDK variant."""
from pathlib import Path
import hashlib
import json
import subprocess

root = Path('/output/opt/openssl')
records = json.loads((root / 'build.json').read_text())
manifest = []
for version in records:
    sdk = root / version
    binary = sdk / 'bin/conditioned_server'
    subprocess.run(['gcc', '-std=c99', '-D_POSIX_C_SOURCE=200809L', '-Wall', '-Wextra', '-Werror', '-O2', '-I' + str(sdk / 'include'), '/lab-source/conditioned_server.c', str(sdk / 'lib/libssl.a'), str(sdk / 'lib/libcrypto.a'), '-ldl', '-pthread', '-o', str(binary)], check=True)
    manifest.append(hashlib.sha256(binary.read_bytes()).hexdigest() + '  ' + str(binary.relative_to(root)))
(root / 'conditioned-binaries.sha256').write_text('\n'.join(manifest) + '\n')
