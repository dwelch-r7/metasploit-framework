"""Run a genuine database client, retain PCAP, and independently verify its bytes."""
import base64
import json
import sys
sys.dont_write_bytecode=True
from controls import ACCOUNTS,NativeClients,mysql_arguments,mysql_wire
from protocols import mysql_greeting,mysql_packets,tds_packets,tds_login7

request=json.loads(sys.argv[1]);clients=NativeClients();profile=request['profile'];kind=request['kind'];host=request['host'];port=request['port'];label=request['label'];client_ip=request['client_ip']
username=kind.get('username',ACCOUNTS['username']);password=kind.get('password',ACCOUNTS['password']);database=None if kind.get('without_database') else ACCOUNTS['database']
role=kind.get('client','oracle_client')
if profile=='mysql':
    if kind.get('no_auth'):
        role='client';argv=['python3','/opt/module-target-database-client.py','greeting','--host',host,'--port',str(port)]
    else:argv=mysql_arguments(role,host,port,username,password,database,tls=kind.get('tls',False),default_tls=kind.get('default_tls',False))
else:
    role='client'
    if kind.get('no_auth'):argv=['python3','/opt/module-target-database-client.py','prelogin','--host',host,'--port',str(port),'--hex',request['prelogin_hex']]
    else:
        if kind.get('ntlm'):
            username=ACCOUNTS['ntlm_domain']+'\\'+ACCOUNTS['ntlm_username'];password=ACCOUNTS['ntlm_password']
        argv=['env','CAPTURE_USERNAME='+username,'CAPTURE_PASSWORD='+password,'python3','/opt/module-target-database-client.py','tsql','--host',host,'--port',str(port),'--database',database or 'master','--tds',kind.get('tds','7.1'),'--ntlm',kind.get('ntlm','yes')]
result=clients.capture(label,port,role,*argv)
streams=json.loads((clients.artifacts/(label+'.wire.json')).read_text());response={'result':result,'wire':streams}
try:
    if profile=='mysql':
        if kind.get('no_auth') or kind.get('tls'):
            inbound=next(s for s in streams if s['target']==client_ip)
            greeting=mysql_greeting(mysql_packets(base64.b64decode(inbound['base64']))[0][1]);response['decoded']={'greeting':{**greeting,'seed':greeting['seed'].hex()}}
            outgoing=[packet for stream in streams if stream['source']==client_ip for packet in mysql_packets(base64.b64decode(stream['base64']))]
            assert not outgoing or kind.get('tls') and all(len(body)==32 and int.from_bytes(body[:4],'little')&0x800 for _,body in outgoing)
            response['decoded']['client_packet_count']=len(outgoing)
        else:response['decoded']=mysql_wire(streams,client_ip,password)
    else:
        inbound=[packet for stream in streams if stream['target']==client_ip for packet in tds_packets(base64.b64decode(stream['base64']))]
        outbound=[packet for stream in streams if stream['source']==client_ip for packet in tds_packets(base64.b64decode(stream['base64']))]
        if kind.get('no_auth'):
            assert [packet['type'] for packet in outbound]==[18]
            assert inbound[0]['type']==4
            response['decoded']={'prelogin_only':True}
        elif kind.get('ntlm'):
            type2=next(packet['payload'][packet['payload'].index(b'NTLMSSP\0'):] for packet in inbound if b'NTLMSSP\0' in packet['payload'])
            type3=next(packet['payload'][packet['payload'].index(b'NTLMSSP\0'):] for packet in outbound if packet['type']==17)
            verifier=clients.command('client','python3','/opt/module-target-ntlm.py',json.dumps({'type2':type2.hex(),'type3':type3.hex(),'password':password}))
            assert verifier['status']==0,verifier
            response['decoded']=json.loads(verifier['stdout'])
            response['decoded']['type2_hex']=type2.hex();response['decoded']['type3_hex']=type3.hex()
        else:response['decoded']=tds_login7(next(packet['payload'] for packet in outbound if packet['type']==16))
except (AssertionError,ValueError,IndexError,StopIteration,KeyError) as error:
    response['analysis_error']=type(error).__name__+': '+str(error)
(clients.artifacts/(label+'-client.json')).write_text(json.dumps(response,indent=2)+'\n')
print(json.dumps(response))
