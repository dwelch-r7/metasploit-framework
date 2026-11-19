"""Read native package, source, server process, configuration and SQLite state."""
from pathlib import Path
import hashlib
import importlib.metadata as metadata
import json
import sqlite3

import pyload

root = Path(pyload.__file__).parent
names = ['core/utils/misc.py', 'webui/app/blueprints/cnl_blueprint.py',
         'plugins/addons/ClickNLoad.py', 'plugins/addons/UpdateManager.py']
sources = {name: hashlib.sha256((root / name).read_bytes()).hexdigest() for name in names}
processes = []
for path in Path('/proc').glob('[0-9]*'):
    try:
        args = [value for value in (path / 'cmdline').read_bytes().split(b'\0') if value]
        # S6's startup wrapper also contains "pyload" among its arguments.
        if len(args) < 2 or not Path(args[0].decode()).name.startswith('python') or Path(args[1].decode()).name != 'pyload':
            continue
        status = dict(line.split(':', 1) for line in (path / 'status').read_text().splitlines())
        processes.append({'pid': int(path.name), 'uid': int(status['Uid'].split()[0]),
                          'gid': int(status['Gid'].split()[0]), 'argv': [value.decode(errors='replace') for value in args]})
    except FileNotFoundError:
        # A short-lived process can exit between the two /proc reads.
        continue

configuration = Path('/config/settings/pyload.cfg')
database = sqlite3.connect('file:/config/data/pyload.db?mode=ro', uri=True)
database.row_factory = sqlite3.Row
try:
    tables = {table: [dict(row) for row in database.execute('SELECT * FROM ' + table + ' ORDER BY id')]
              for table in ['users', 'packages', 'links']}
finally:
    database.close()
print('NATIVE_JSON=' + json.dumps({'package': metadata.version('pyload-ng'), 'sources': sources,
                                  'processes': processes, 'configuration_sha256': hashlib.sha256(configuration.read_bytes()).hexdigest(),
                                  'configuration': configuration.read_text(), 'tables': tables}))
