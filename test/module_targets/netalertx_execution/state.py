"""Read target-native process, queue, configuration and API state without mutation."""
import ast
import json
import socket
from pathlib import Path

root = Path('/app')
backend = []
for item in Path('/proc').iterdir():
    if not item.name.isdigit():
        continue
    try:
        argv = [part.decode() for part in (item / 'cmdline').read_bytes().split(b'\0') if part]
        if len(argv) != 2 or argv[1] != '/app/server':
            continue
        fields = (item / 'stat').read_text().rsplit(') ', 1)[1].split()
        backend.append(dict(pid=int(item.name), parent=int(fields[1]), birth=fields[19], argv=argv, uid=item.stat().st_uid))
    except (FileNotFoundError, ProcessLookupError):
        continue
configuration = {}
all_configuration = {}
for statement in ast.parse((root / 'config/app.conf').read_text()).body:
    if isinstance(statement, ast.Assign) and len(statement.targets) == 1 and isinstance(statement.targets[0], ast.Name):
        key = statement.targets[0].id
        all_configuration[key] = ast.literal_eval(statement.value)
        if key.endswith('_RUN') or key.startswith('DBCLNP_') or key in ['SCAN_SUBNETS', 'SETPWD_enable_password', 'LOADED_PLUGINS']:
            configuration[key] = ast.literal_eval(statement.value)
api_error = None
try:
    settings = json.loads((root / 'front/api/table_settings.json').read_text())['data']
    settings = {row['Code_Name']: row['Value'] for row in settings if row['Code_Name'].startswith('DBCLNP_') or row['Code_Name'] in ['SCAN_SUBNETS', 'SETPWD_enable_password']}
    plugins = [row['unique_prefix'] for row in json.loads((root / 'front/api/plugins.json').read_text())['data']]
except json.JSONDecodeError as error:
    settings, plugins, api_error = {}, [], str(error)
proof = Path('/tmp/module-target-netalertx-native-proof')
cgroups = {}
for name in ['memory.events', 'pids.events']:
    cgroups[name] = dict(line.split() for line in (Path('/sys/fs/cgroup') / name).read_text().splitlines())
state = dict(backend=backend, configuration=configuration, settings=settings, plugins=plugins, api_error=api_error,
             all_configuration=all_configuration,
             address=socket.gethostbyname(socket.gethostname()),
             queue=(root / 'front/log/execution_queue.log').read_text(),
             marker=proof.read_text() if proof.exists() else '', marker_uid=proof.stat().st_uid if proof.exists() else None,
             init_birth=Path('/proc/1/stat').read_text().rsplit(') ', 1)[1].split()[19], cgroups=cgroups)
print(json.dumps(state))
