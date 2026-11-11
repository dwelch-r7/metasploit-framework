"""Read-only independent evidence inside the controlled target; never repair it."""
import base64
import hashlib
import json
from pathlib import Path
import re
import sqlite3
import sys

options = json.loads(sys.argv[1])
root = Path('/app/superset')
result = {}
if options['action'] == 'sources':
    for name in options['files']:
        relative = Path(name)
        assert not relative.is_absolute() and '..' not in relative.parts
        data = (root / relative).read_bytes()
        result[name] = {'sha256': hashlib.sha256(data).hexdigest(), 'bytes_base64': base64.b64encode(data).decode()}
elif options['action'] == 'snapshot':
    connection = sqlite3.connect('file:/app/superset_home/superset.db?mode=ro', uri=True)
    connection.row_factory = sqlite3.Row
    for table in ['ab_user', 'tab_state', 'table_schema', 'key_value']:
        result[table] = [{key: {'bytes_base64': base64.b64encode(value).decode()} if isinstance(value, bytes) else value
                          for key, value in dict(row).items()}
                         for row in connection.execute('SELECT * FROM ' + table + ' ORDER BY id')]
elif options['action'] == 'marker':
    path = Path(options['path'])
    assert re.fullmatch(r'/tmp/module-target-native-[0-9a-f]{32}', str(path))
    result = {'exists': path.exists(), 'content': path.read_text() if path.exists() else None}
else:
    raise ValueError('Unknown read-only observation')
print('MODULE-TARGET-RCE-JSON:' + json.dumps(result, default=str))
