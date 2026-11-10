"""Prove native SQL Server/FreeTDS and inspect actual cleartext LOGIN7/SSPI bytes."""
import base64
import json
from pathlib import Path
import sys
sys.dont_write_bytecode=True
sys.path.insert(0,'test/module_targets/database_capture')
from controls import NativeClients,ACCOUNTS,sql_string
from protocols import tds_packets,tds_login7

clients=NativeClients()
def command(service,*args,**kwargs):
    result=clients.command(service,*args,**kwargs)
    assert result['status']==0,result
    return result
identity=command('client','python3','/opt/module-target-client.py','identity')
client_ip=json.loads(identity['stdout'])['client_ip']
version=command('client','tsql','-C');assert 'freetds v1.3.17' in version['stdout']
crypto=command('client','python3','-c','from Cryptodome.Hash import MD4;from Cryptodome.Cipher import DES;print(MD4.new(b"module-target").hexdigest())');assert '1578a3fa8ad9b284992d5b126cc48c0f' in crypto['stdout']
user=ACCOUNTS['username'];db=ACCOUNTS['database'];password=ACCOUNTS['password']
sql="IF DB_ID(N'"+db+"') IS NULL CREATE DATABASE ["+db+"];\nGO\nIF NOT EXISTS (SELECT 1 FROM sys.sql_logins WHERE name="+sql_string(user)+") CREATE LOGIN ["+user+"] WITH PASSWORD="+sql_string(password)+", CHECK_POLICY=OFF;\nIF NOT EXISTS (SELECT 1 FROM sys.sql_logins WHERE name='capture_empty') CREATE LOGIN [capture_empty] WITH PASSWORD='', CHECK_POLICY=OFF;\nGO\nUSE ["+db+"];\nIF NOT EXISTS (SELECT 1 FROM sys.database_principals WHERE name="+sql_string(user)+") CREATE USER ["+user+"] FOR LOGIN ["+user+"];\nIF NOT EXISTS (SELECT 1 FROM sys.database_principals WHERE name='capture_empty') CREATE USER [capture_empty] FOR LOGIN [capture_empty];\nSELECT name,is_policy_checked FROM master.sys.sql_logins WHERE name LIKE 'capture%';\nSELECT @@VERSION;\nGO\n"
seed=command('native_mssql','/opt/mssql-tools18/bin/sqlcmd','-S','localhost','-U','sa','-P','yourStrong(!)Password','-C','-b','-W',stdin=sql.encode(),timeout=40)
assert '15.0.4500.2' in seed['stdout'] and 'capture_empty 0' in seed['stdout'],seed
proofs=[];prelogin=None
for tds in ['7.1','7.4']:
    for kind,username,secret in [('edge',user,password),('empty',ACCOUNTS['empty_username'],''),('rejected',user,ACCOUNTS['rejected_password']),('ntlm',ACCOUNTS['ntlm_domain']+'\\'+ACCOUNTS['ntlm_username'],ACCOUNTS['ntlm_password'])]:
        label='native-mssql-'+tds.replace('.','')+'-'+kind
        result=clients.capture(label,1433,'client','env','CAPTURE_USERNAME='+username,'CAPTURE_PASSWORD='+secret,'python3','/opt/module-target-database-client.py','tsql','--host','native_mssql','--port','1433','--database',db,'--tds',tds)
        streams=json.loads((clients.artifacts/(label+'.wire.json')).read_text())
        outbound=[tds_packets(base64.b64decode(s['base64'])) for s in streams if s['source']==client_ip]
        assert len(outbound)==1,outbound
        packets=outbound[0];login=next(p for p in packets if p['type']==16)
        if prelogin is None:
            stream=next(s for s in streams if s['source']==client_ip)
            raw=base64.b64decode(stream['base64']);size=int.from_bytes(raw[2:4],'big');prelogin=raw[:size].hex()
        if kind=='ntlm':
            assert result['status']!=0 and 'NTLMSSP\x00' in login['payload'].decode('latin1'),result
            assert 'untrusted domain' in result['stderr'].lower(),result
            proofs.append({'label':label,'ntlm_type1_hex':login['payload'][login['payload'].index(b'NTLMSSP\0'):].hex(),'native_domain_authentication':'rejected: no domain backend configured'})
        else:
            decoded=tds_login7(login['payload'])
            assert decoded['username']==username and decoded['password']==secret and decoded['database']==db,decoded
            if kind=='rejected':assert result['status']!=0 and 'Login failed' in result['stderr'],result
            else:assert result['status']==0 and username+'\t'+db+'\tMicrosoft SQL Server 2019' in result['stdout'] and 'module-target-tds-native' in result['stdout'],result
            proofs.append({'label':label,'login':decoded})
pre=clients.capture('native-mssql-prelogin-only',1433,'client','python3','/opt/module-target-database-client.py','prelogin','--host','native_mssql','--port','1433','--hex',prelogin)
assert pre['status']==0 and json.loads(pre['stdout'])['response_hex'].startswith('0401'),pre
schema=command('reporting_db','env','PGPASSWORD=module-target-framework-db-password','psql','-h','127.0.0.1','-U','module_framework','-d','module_targets','-Atc',"SELECT count(*) FROM information_schema.tables WHERE table_schema='public'")
assert schema['stdout'].strip()=='0',schema
output={'client_ip':client_ip,'commands':clients.commands,'wire_captures':sorted(p.name for p in clients.artifacts.glob('native-*.pcap')),'proofs':proofs,'prelogin_hex':prelogin}
(clients.artifacts/'native-mssql.json').write_text(json.dumps(output,indent=2)+'\n')
print(json.dumps(output))
