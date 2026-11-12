"""Preserve genuine async master job returns before the target is removed."""
import base64
import json
from pathlib import Path

import salt.config
import salt.payload

serial = salt.payload.Serial(salt.config.master_config('/etc/salt/master'))
results = []
for path in sorted(Path('/var/cache/salt/master/jobs').rglob('return.p')):
    results.append({'path': str(path), 'result': serial.loads(path.read_bytes())})


def encode(value):
    if isinstance(value, bytes):
        return {'bytes_base64': base64.b64encode(value).decode()}
    raise TypeError(type(value).__name__)


print('SALT_JOBS=' + json.dumps(results, default=encode))
