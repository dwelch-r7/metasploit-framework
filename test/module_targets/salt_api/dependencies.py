"""Check the pinned runtime, including Salt's supported Cryptodome backend."""

import json
import shutil
import subprocess
import sys

import cherrypy
import salt.crypt
import salt.version


result = subprocess.run([sys.executable, '-m', 'pip', 'check'], capture_output=True, text=True, check=False)
lines = result.stdout.strip().splitlines()
# Salt 3000's Linux package metadata names pycrypto, but salt/crypt.py explicitly
# prefers Cryptodome. Keep the existing pinned backend and allow only this exact
# metadata discrepancy; every other missing/incompatible package fails the build.
expected = ['salt {} requires pycrypto, which is not installed.'.format(salt.version.__version__)]
assert (result.returncode == 0 and not result.stderr.strip()) or (result.returncode == 1 and lines == expected and not result.stderr.strip()), (result.stdout, result.stderr)
assert salt.crypt.HAS_CDOME
assert cherrypy.__version__ == '18.6.0'
tools = {name: shutil.which(name) for name in ['ssh', 'ssh-keygen', 'openssl']}
assert all(tools.values()), tools
print(json.dumps(dict(salt=salt.version.__version__, cryptodome=salt.crypt.HAS_CDOME, tools=tools, metadata_exceptions=lines if result.returncode else [])))
