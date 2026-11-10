"""Bind every requested interface through Samba's native DCE/RPC client."""
import json
import sys
from samba.dcerpc import base
from samba.credentials import Credentials
from samba.param import LoadParm

lp = LoadParm()
lp.load('/opt/module-target-client.conf')
credentials = Credentials()
credentials.guess(lp)
credentials.set_username('rpc_admin')
credentials.set_password('Module-target-rpc-admin-2026!')
rows = []
pairs = json.load(sys.stdin)
for pipe in ['BROWSER', 'samr', 'module_missing']:
    for uuid, version in pairs:
        major, minor = map(int, version.split('.'))
        row = dict(pipe=pipe, uuid=uuid, version=version)
        try:
            connection = base.ClientConnection('ncacn_np:samba[\\pipe\\'+pipe+']', (uuid, major+(minor << 16)), lp, credentials)
            row.update(status='OPEN', abstract_syntax=connection.abstract_syntax)
            del connection
        except Exception as error:
            row.update(status='ERROR', error=type(error).__name__, args=error.args)
        rows.append(row)
print(json.dumps(rows))
