"""Preserve genuine async master job returns before the target is removed."""
import json
from pathlib import Path
import sys

import salt.config
import salt.payload

sys.path.insert(0, '/opt/module-target')
from job_control import MAX_REPORT_BYTES, encode, read_bytes, transient_cache_read

options = salt.config.master_config('/etc/salt/master')
serial = salt.payload.Serial(options)


def snapshot():
    results = []
    for path in sorted((Path(options['cachedir']) / 'jobs').rglob('return.p')):
        if len(results) >= 256:
            raise ValueError('Job cache evidence exceeds its 256-row observation bound; history is retained')
        value = serial.loads(read_bytes(path))
        jid_file = path.parent.parent / 'jid'
        results.append({'path': str(path), 'jid': read_bytes(jid_file).decode().strip(),
                        'node': path.parent.name, 'result': value,
                        'success': value.get('success') if isinstance(value, dict) else None,
                        'retcode': value.get('retcode') if isinstance(value, dict) else None})
    return results


document = json.dumps(transient_cache_read(snapshot), default=encode)
if len(document.encode()) > MAX_REPORT_BYTES:
    raise ValueError('Job cache JSON exceeds its 512-KiB observation bound; history is retained')
print('SALT_JOBS=' + document)
