import ast
import base64
import builtins
import contextlib
import io
import json
import os
import pickle
from pathlib import Path
import subprocess
import sys
import threading

request = json.load(sys.stdin)
if request.get('generator'):
    source = Path(request['generator']).read_text().replace("'#{escaped}'", repr(request['code']))
    generated = subprocess.check_output([sys.executable, '-c', source], timeout=3)
    serialized = ast.literal_eval(generated.decode().strip()).encode('raw_unicode_escape')
    print(json.dumps({'payload': base64.b64encode(serialized).decode()}))
    sys.exit(0)

errors = []
threading.excepthook = lambda error: errors.append({
    'type': error.exc_type.__name__, 'message': str(error.exc_value)
})
builtins._msf_deserialization_started = threading.Event()
builtins._msf_deserialization_release = threading.Event()
original_keys = set(vars(threading))
output = io.StringIO()
returns = []
alive = []
with contextlib.redirect_stdout(output):
    for encoded in request['payloads']:
        before = set(threading.enumerate())
        returns.append(pickle.loads(base64.b64decode(encoded)))
        if request.get('release'):
            builtins._msf_deserialization_started.wait(2)
            builtins._msf_deserialization_release.set()
        for thread in set(threading.enumerate()) - before:
            thread.join(2)
            if thread.is_alive():
                alive.append(thread.name)

print(json.dumps({
    'stdout': output.getvalue(), 'errors': errors, 'returns': returns,
    'alive': alive, 'threading_keys_added': sorted(set(vars(threading)) - original_keys),
    'python': sys.version, 'executable': sys.executable
}), flush=True)
if alive:
    os._exit(1)
