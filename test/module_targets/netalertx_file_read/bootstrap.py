"""Initialize the real vendor DB/config without running discovery or cron loops."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import sys
import time

root = Path('/app')
for name in ['config', 'db', 'front/log', 'front/api']:
    (root / name).mkdir(parents=True, exist_ok=True)
shutil.copyfile(root / 'back/app.db', root / 'db/app.db')
configuration = (root / 'back/app.conf').read_text()
# Every plugin RUN setting is disabled before the real importer evaluates it.
# SETPWD's template supplies the application's ordinary login configuration.
settings = {'SCAN_SUBNETS': [], 'LOADED_PLUGINS': ['SETPWD'], 'TIMEZONE': 'UTC',
            'UI_LANG': 'English', 'LOG_LEVEL': 'none',
            'SETPWD_enable_password': os.environ.get('WEB_PROTECTION', 'true') == 'true',
            'SETPWD_password': hashlib.sha256(b'module-target-netalertx-password').hexdigest(),
            'SYNC_api_token': 'module-target-netalertx-token'}
for source in sorted((root / 'front/plugins').glob('*/config.json')):
    plugin = json.loads(source.read_text())
    settings[plugin['unique_prefix'] + '_RUN'] = 'disabled'
configuration += '\n# Disposable module target settings\n' + ''.join(f'{key} = {value!r}\n' for key, value in settings.items())
(root / 'config/app.conf').write_text(configuration)
for name in ['app.log', 'execution_queue.log', 'app_front.log', 'app.php_errors.log',
             'stderr.log', 'stdout.log', 'db_is_locked.log']:
    (root / 'front/log' / name).touch()
(root / 'front/api/user_notifications.json').write_text('[]')
# The vendor entrypoint normally creates this timestamp before backend startup.
(root / 'front/buildtimestamp.txt').write_text(str(int(time.time())))
# Its initial release check has no timeout. A refused loopback proxy makes that
# optional check fail immediately without contacting an external service.
os.environ['HTTPS_PROXY'] = 'http://127.0.0.1:9'
os.environ['HTTP_PROXY'] = 'http://127.0.0.1:9'
sys.path.insert(0, '/app/server')
from database import DB
from initialise import importConfigs
from api import update_api
from notification import Notification_obj

database = DB()
database.open()
database.upgradeDB()
Notification_obj(database)
plugins = importConfigs(database, None)
update_api(database, plugins)
database.commitDB()
assert database.sql.execute("SELECT Value FROM Settings WHERE Code_Name='UI_LANG'").fetchone()[0] == 'English'
database.sql_connection.close()
# Files outside the web root have deterministic bytes and ordinary read access.
proofs = Path('/tmp/module-target-netalertx')
proofs.mkdir()
content = b'NetAlertX native proof\n<node>& "quoted"\nsecond line\n'
for name in ['proof.txt', 'space name.txt', 'quote"name.txt']:
    (proofs / name).write_bytes(content)
(proofs / 'empty.txt').write_bytes(b'')
summary = {'version': (root / '.VERSION').read_text().strip(),
           'web_protection': settings['SETPWD_enable_password'],
           'initialized_plugins': [p['unique_prefix'] for p in plugins],
           'proof_sha256': hashlib.sha256(content).hexdigest()}
Path('/tmp/module-target-netalertx-bootstrap.json').write_text(json.dumps(summary) + '\n')
print('MODULE_TARGET_NETALERTX_BOOTSTRAP=' + json.dumps(summary), flush=True)
