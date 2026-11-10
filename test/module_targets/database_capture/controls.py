"""Family-local commands and independently decoded actual database-client bytes."""
import base64
import json
from pathlib import Path
import sys

sys.dont_write_bytecode = True
sys.path.insert(0, 'test/module_targets/capture_core')
from native_client import NativeClients
from protocols import mysql_greeting, mysql_login, mysql_native_response, mysql_packets

ACCOUNTS = json.loads(Path('test/module_targets/database_capture/accounts.json').read_text())


def mysql_arguments(service, host, port, user, password, database=None, tls=False, default_tls=False):
    binary = 'mysql' if service == 'oracle_client' else 'mariadb'
    args = [binary, '--no-defaults', '--protocol=TCP', '--host='+host, '--port='+str(port), '--user='+user, '--password='+password, '--connect-timeout=2', '--batch', '--skip-column-names']
    if not default_tls:
        args += ['--ssl-mode=REQUIRED' if tls else '--ssl-mode=DISABLED'] if service == 'oracle_client' else ['--skip-ssl']
    if database is not None:
        args.append('--database='+database)
    return args + ['--execute=SELECT CURRENT_USER(),DATABASE(),VERSION(),\'module-target-database-native\'']


def mysql_wire(streams, client_ip, password=None):
    inbound = [mysql_packets(base64.b64decode(s['base64'])) for s in streams if s['target'] == client_ip]
    outbound = [mysql_packets(base64.b64decode(s['base64'])) for s in streams if s['source'] == client_ip]
    assert len(inbound) == len(outbound) == 1, streams
    server, client = inbound[0], outbound[0]
    greeting = mysql_greeting(server[0][1])
    login = mysql_login(client[0][1])
    if password is not None and not login.get('ssl_request'):
        switch = next((body for _,body in server[1:] if body.startswith(b'\xfemysql_native_password\0')), None)
        if switch:
            plugin, seed = switch[1:].split(b'\0',1)
            assert plugin == b'mysql_native_password', plugin
            challenge = seed[:20]
            response = client[1][1]
        else:
            challenge, response = greeting['seed'], login['response']
            assert login.get('plugin') in (None,'mysql_native_password'), login
        assert len(challenge) == 20
        expected = mysql_native_response(password,challenge) if password else b''
        assert len(response) == (20 if password else 0)
        assert expected == response, (response.hex(),challenge.hex())
    else:
        challenge, response = greeting['seed'], login.get('response',b'')
    return {'greeting':{**greeting,'seed':greeting['seed'].hex()},'login':{**login,'response':login.get('response',b'').hex()},'native_challenge':challenge.hex(),'native_response':response.hex()}


def sql_string(value):
    return "'" + value.replace("'", "''") + "'"


def mysql_seed(clients, service):
    import hashlib
    fixture = [('edge',ACCOUNTS['username'],ACCOUNTS['password']),('tail_0','capture_tail0',ACCOUNTS['tail_0_password']),('tail_32','capture_tail32',ACCOUNTS['tail_32_password']),('empty',ACCOUNTS['empty_username'],'')]
    statements=['CREATE DATABASE IF NOT EXISTS `'+ACCOUNTS['database']+'`;']
    for _,user,password in fixture:
        first=hashlib.sha1(password.encode()).digest()
        hashed='*'+hashlib.sha1(first).hexdigest().upper() if password else ''
        account=sql_string(user)+"@'%'"
        statements.append('DROP USER IF EXISTS '+account+';')
        method='IDENTIFIED WITH mysql_native_password AS ' if service=='native_mysql' else 'IDENTIFIED VIA mysql_native_password USING '
        statements.append('CREATE USER '+account+' '+method+sql_string(hashed)+';')
        statements.append('GRANT SELECT ON `'+ACCOUNTS['database']+'`.* TO '+account+';')
    statements.append("SELECT user,host,plugin FROM mysql.user WHERE user LIKE 'capture%';")
    args=['mysql' if service=='native_mysql' else 'mariadb','-uroot','-ppassword','--batch','--skip-column-names']
    receipt=clients.command(service,*args,stdin=('\n'.join(statements)+'\n').encode())
    assert receipt['status']==0,receipt
    assert receipt['stdout'].count('mysql_native_password')==4,receipt
    return fixture
