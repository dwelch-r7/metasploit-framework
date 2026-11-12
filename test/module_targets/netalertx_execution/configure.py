"""Configure a genuine backend while preventing unrelated discovery schedules."""
from pathlib import Path
import grp
import os
import pwd
import re

configuration = Path('/app/config/app.conf')
configuration.write_text(configuration.read_text() + "\n# Controlled execution baseline\nDBCLNP_RUN = 'schedule'\nDBCLNP_CMD = '/bin/echo module-target-original-command'\nDBCLNP_RUN_SCHD = '59 23 31 12 *'\nDBCLNP_RUN_TIMEOUT = 30\n")
# Retain the vendor supervisors and NGINX/FPM configuration with bounded workers.
Path('/run/nginx').mkdir(parents=True, exist_ok=True)
Path('/run/php').mkdir(parents=True, exist_ok=True)
sessions = Path('/var/lib/php83/sessions')
sessions.mkdir(parents=True, exist_ok=True)
os.chown(sessions, pwd.getpwnam('nginx').pw_uid, grp.getgrnam('www-data').gr_gid)
p = Path('/etc/nginx/nginx.conf')
p.write_text(re.sub(r'^worker_processes .*', 'worker_processes 1;', p.read_text(), flags=re.M))
p = Path('/etc/php83/php-fpm.d/www.conf')
text = p.read_text()
for name, value in [('pm.max_children', 3), ('pm.start_servers', 1), ('pm.min_spare_servers', 1), ('pm.max_spare_servers', 2)]:
    text = re.sub('^' + re.escape(name) + r' =.*', name + ' = ' + str(value), text, flags=re.M)
p.write_text(text)
