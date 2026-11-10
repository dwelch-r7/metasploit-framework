"""Invoke installed FreeTDS or make a credential-free native socket connection."""
import argparse
import json
import os
import socket
import subprocess
import sys

parser=argparse.ArgumentParser()
parser.add_argument('mode',choices=['tsql','greeting','connect','prelogin'])
parser.add_argument('--host',required=True)
parser.add_argument('--port',type=int,required=True)
parser.add_argument('--tds',default='7.1')
parser.add_argument('--ntlm',choices=['yes','no'],default='yes')
parser.add_argument('--database',default='master')
parser.add_argument('--hex')
args=parser.parse_args()
if args.mode=='tsql':
    config='[capture]\nhost = '+args.host+'\nport = '+str(args.port)+'\ntds version = '+args.tds+'\nencryption = off\nuse ntlmv2 = '+args.ntlm+'\nclient charset = UTF-8\n'
    open('/tmp/module-target-freetds.conf','w').write(config)
    environment={**os.environ,'FREETDSCONF':'/tmp/module-target-freetds.conf','TDSDUMPCONFIG':'/tmp/module-target-freetds-config.log'}
    result=subprocess.run(['tsql','-S','capture','-U',os.environ['CAPTURE_USERNAME'],'-P',os.environ['CAPTURE_PASSWORD'],'-D',args.database],input=b"SELECT SUSER_SNAME(),DB_NAME(),@@VERSION,'module-target-tds-native'\ngo\nquit\n",capture_output=True,timeout=7,env=environment)
    sys.stdout.buffer.write(result.stdout);sys.stderr.buffer.write(result.stderr)
    raise SystemExit(result.returncode)
with socket.create_connection((args.host,args.port),timeout=2) as connection:
    connection.settimeout(2)
    if args.mode=='prelogin':
        connection.sendall(bytes.fromhex(args.hex))
        data=connection.recv(4096)
        print(json.dumps({'response_hex':data.hex()}))
    elif args.mode=='greeting':
        header=connection.recv(4)
        if len(header)!=4:raise ValueError('Incomplete greeting header')
        length=int.from_bytes(header[:3],'little')
        body=b''
        while len(body)<length:
            fragment=connection.recv(length-len(body))
            if not fragment:raise ValueError('Incomplete greeting')
            body+=fragment
        print(json.dumps({'greeting_hex':(header+body).hex()}))
    else:
        print(json.dumps({'connected':True}))
