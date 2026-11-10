"""Prove genuine Oracle and MariaDB clients, accounts and challenge-response bytes."""
import base64
import json
from pathlib import Path
import sys
sys.dont_write_bytecode=True
sys.path.insert(0,'test/module_targets/database_capture')
from controls import ACCOUNTS, NativeClients, mysql_arguments, mysql_seed, mysql_wire

clients=NativeClients()
identity=clients.command('client','python3','/opt/module-target-client.py','identity')
assert identity['status']==0,identity
client_ip=json.loads(identity['stdout'])['client_ip']
for role,version in [('oracle_client','8.0.36'),('mariadb_client','11.2.2')]:
    result=clients.command(role,'mysql' if role=='oracle_client' else 'mariadb','--version')
    assert result['status']==0 and version in result['stdout'],result
proofs=[]
for service,version in [('native_mysql','8.0.36'),('native_mariadb','11.2.2')]:
    fixture=mysql_seed(clients,service)
    for role in ['oracle_client','mariadb_client']:
        for kind,user,password in fixture:
            label='native-'+service+'-'+role+'-'+kind
            result=clients.capture(label,3306,role,*mysql_arguments(role,service,3306,user,password,ACCOUNTS['database']))
            assert result['status']==0,result
            assert user+'@%\t'+ACCOUNTS['database']+'\t'+version in result['stdout'],result
            wire=json.loads((clients.artifacts/(label+'.wire.json')).read_text())
            decoded=mysql_wire(wire,client_ip,password)
            assert decoded['login']['username']==user and decoded['login']['database']==ACCOUNTS['database'],decoded
            if not password:assert decoded['native_response']=='',decoded
            proofs.append({'label':label,**decoded})
        label='native-'+service+'-'+role+'-rejected'
        result=clients.capture(label,3306,role,*mysql_arguments(role,service,3306,ACCOUNTS['username'],ACCOUNTS['rejected_password'],ACCOUNTS['database']))
        assert result['status']!=0 and '1045' in result['stderr'],result
        decoded=mysql_wire(json.loads((clients.artifacts/(label+'.wire.json')).read_text()),client_ip,ACCOUNTS['rejected_password'])
        proofs.append({'label':label,**decoded})
for role in ['oracle_client','mariadb_client']:
    label='native-mysql-default-'+role
    result=clients.capture(label,3306,role,*mysql_arguments(role,'native_mysql',3306,ACCOUNTS['username'],ACCOUNTS['password'],ACCOUNTS['database'],default_tls=True))
    assert result['status']==0 and ACCOUNTS['username']+'@%\t'+ACCOUNTS['database']+'\t8.0.36' in result['stdout'],result
    streams=json.loads((clients.artifacts/(label+'.wire.json')).read_text())
    outgoing=base64.b64decode(next(s['base64'] for s in streams if s['source']==client_ip))
    first_length=int.from_bytes(outgoing[:3],'little');first=outgoing[4:4+first_length]
    flags=int.from_bytes(first[:4],'little')
    if flags&0x800:
        assert first_length==32 and outgoing[4+first_length:5+first_length]==b'\x16',outgoing.hex()
        proofs.append({'label':label,'default_tls':'SSLRequest and actual TLS records; native SQL identity succeeded','client_flags':flags})
    else:proofs.append({'label':label,'default_tls':'client elected plaintext',**mysql_wire(streams,client_ip,ACCOUNTS['password'])})
greeting=clients.capture('native-mysql-greeting-only',3306,'client','python3','/opt/module-target-database-client.py','greeting','--host','native_mysql','--port','3306')
assert greeting['status']==0 and json.loads(greeting['stdout'])['greeting_hex'][8:10]=='0a',greeting
schema=clients.command('reporting_db','env','PGPASSWORD=module-target-framework-db-password','psql','-h','127.0.0.1','-U','module_framework','-d','module_targets','-Atc',"SELECT count(*) FROM information_schema.tables WHERE table_schema='public'")
assert schema['status']==0 and schema['stdout'].strip()=='0',schema
zero_seed=next(proof['native_challenge'] for proof in proofs if '0' in proof.get('native_challenge',''))
output={'client_ip':client_ip,'commands':clients.commands,'wire_captures':sorted(p.name for p in clients.artifacts.glob('native-*.pcap')),'proofs':proofs,'zero_challenge':zero_seed}
(clients.artifacts/'native-mysql.json').write_text(json.dumps(output,indent=2)+'\n')
print(json.dumps(output))
