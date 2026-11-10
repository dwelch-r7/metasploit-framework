"""Authenticate actual clients against genuine fixtures before any Framework capture job."""
import json
import os
from pathlib import Path
import sys

sys.dont_write_bytecode = True
from native_client import NativeClients

clients = NativeClients()
accounts = json.loads(Path('test/module_targets/capture_core/accounts.json').read_text())
username = accounts['username']


def command(service, *args, stdin=None, status=0):
    receipt = clients.command(service, *args, stdin=stdin)
    assert receipt['status'] == status, receipt
    return receipt


def curl(label, protocol, password, *args, status=0):
    port = 21 if protocol == 'ftp' else 80
    user = username + ':' + password
    receipt = clients.capture(label, port, 'curl', 'curl', '--silent', '--show-error', '--connect-timeout', '2', '--max-time', '5', '--noproxy', '*', '--trace-ascii', '-', '--user', user, *args)
    assert receipt['status'] == status, receipt
    return receipt


identity = command('client', 'python3', '/opt/module-target-client.py', 'identity')
curl_identity = command('curl', 'curl', '--version')
assert 'curl 8.13.0' in curl_identity['stdout']
assert all(protocol in curl_identity['stdout'] for protocol in ['ftp', 'http', 'pop3', 'imap', 'smtp'])
client_ip = json.loads(identity['stdout'])['client_ip']
command('native_ftp', 'useradd', '--home-dir', '/srv/ftp', '--shell', '/bin/sh', username)
for kind, password in [('normal', accounts['normal_password']), ('edge', accounts['edge_password'])]:
    command('native_ftp', 'chpasswd', stdin=(username+':'+password+'\n').encode())
    receipt = curl('native-ftp-'+kind, 'ftp', password, '--ftp-method', 'nocwd', 'ftp://native_ftp/module-target.txt')
    assert 'module-target-ftp-marker' in receipt['stdout'], receipt
    assert '230 ' in receipt['stdout'], receipt
wrong = curl('native-ftp-rejected', 'ftp', 'module-target-rejected', 'ftp://native_ftp/module-target.txt', status=67)
assert '530' in wrong['stdout']
for kind, password in [('normal', accounts['normal_password']), ('empty', ''), ('edge', accounts['edge_password'])]:
    command('native_http', 'htpasswd', '-b', '/usr/local/apache2/conf/module-target.htpasswd', username, password)
    receipt = curl('native-http-'+kind, 'http', password, '--anyauth', '--include', 'http://native_http/protected/')
    assert '200 OK' in receipt['stdout'] and 'module-target-protected-marker' in receipt['stdout'], receipt
bearer = clients.capture('native-http-bearer', 80, 'curl', 'curl', '--silent', '--show-error', '--max-time', '5', '--noproxy', '*', '--include', '--header', 'Authorization: Bearer basic-token', 'http://native_http/protected/')
assert bearer['status'] == 0 and '401 Unauthorized' in bearer['stdout'], bearer
sql = b'CREATE ROLE :"username" LOGIN PASSWORD :\'password\';\nCREATE DATABASE :"database" OWNER :"username";\n'
command('native_postgres', 'env', 'PGPASSWORD=password', 'psql', '-h', '127.0.0.1', '-U', 'postgres', '-v', 'ON_ERROR_STOP=1', '-v', 'username='+accounts['pg_username'], '-v', 'password='+accounts['edge_password'], '-v', 'database='+accounts['pg_database'], stdin=sql)
for mode in ['disable', 'prefer', 'require']:
    args = ['env', 'PGHOST=native_postgres', 'PGPORT=5432', 'PGUSER='+accounts['pg_username'], 'PGDATABASE='+accounts['pg_database'], 'PGPASSWORD='+accounts['edge_password'], 'PGAPPNAME=module-target-native-client', 'PGSSLMODE='+mode, 'PGGSSENCMODE=disable', 'PGCONNECT_TIMEOUT=2', 'psql', '-w', '-Atc', "SELECT current_user, current_database(), current_setting('application_name'), version()"]
    result = clients.capture('native-postgres-'+mode, 5432, 'client', *args)
    if mode == 'require':
        assert result['status'] == 2 and 'does not support SSL' in result['stderr'], result
    else:
        assert result['status'] == 0 and accounts['pg_username']+'|'+accounts['pg_database']+'|module-target-native-client|PostgreSQL 16.' in result['stdout'], result
rule = command('native_postgres', 'env', 'PGPASSWORD=password', 'psql', '-h', '127.0.0.1', '-U', 'postgres', '-Atc', 'SELECT type,auth_method,error FROM pg_hba_file_rules ORDER BY line_number')
assert 'scram-sha-256' in rule['stdout'], rule
schema = command('reporting_db', 'env', 'PGPASSWORD=module-target-framework-db-password', 'psql', '-h', '127.0.0.1', '-U', 'module_framework', '-d', 'module_targets', '-Atc', "SELECT count(*) FROM information_schema.tables WHERE table_schema='public'")
assert schema['stdout'].strip() == '0', schema
output = {'client_ip': client_ip, 'commands': clients.commands, 'wire_captures': sorted(p.name for p in clients.artifacts.glob('native-*.pcap'))}
(clients.artifacts/'native-core.json').write_text(json.dumps(output,indent=2)+'\n')
print(json.dumps(output))
