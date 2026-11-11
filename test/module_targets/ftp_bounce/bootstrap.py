"""Configure the normal ProFTPD server; retain the shared FTP fixture files."""
import os
from pathlib import Path

mode = os.environ['MODULE_TARGET_ALLOW_FOREIGN']
assert mode in ['on', 'off']
source = Path('/etc/proftpd/module-target.conf').read_text()
assert source.count('<Anonymous /srv/ftp>') == 1
source = source.replace('ANONYMOUS_LOGIN', 'AllowAll').replace('ANONYMOUS_WRITE', 'DenyAll')
# Set both supported contexts explicitly so local and anonymous logins use the
# same policy. No FTP command handlers or responses are replaced.
setting = 'AllowForeignAddress ' + mode + '\n'
source = setting + source.replace('<Anonymous /srv/ftp>\n', '<Anonymous /srv/ftp>\n  ' + setting)
Path('/etc/proftpd/target.conf').write_text(source)
os.execvp('proftpd', ['proftpd', '--nodaemon', '--debug', '2', '--config', '/etc/proftpd/target.conf'])
