"""Send genuine client requests using the module's bare Via/default-port shape."""
import base64
import json
import select
import socket
import sys
import time
import uuid

operation=json.load(sys.stdin)
account=operation['account'];host=operation['host'];source_port=operation['source_port']
assert account in ['1000','1001'] and source_port in [0,5060]
sender=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);receiver=None
try:
    sender.bind(('0.0.0.0',source_port));sender.connect((host,5060));local=sender.getsockname()
    if source_port==0:
        assert local[1]!=5060
        receiver=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);receiver.bind((local[0],5060))
    identifier=uuid.uuid4().hex
    lines=[f'REGISTER sip:{host} SIP/2.0',f'Via: SIP/2.0/UDP {local[0]}','Max-Forwards: 70',f'To: "{account}"<sip:{account}@{host}>',f'From: "{account}"<sip:{account}@{host}>',f'Call-ID: {identifier}','CSeq: 1 REGISTER','Contact: *','Expires: 0','Content-Length: 0','','']
    request='\r\n'.join(lines).encode();sender.send(request);deadline=time.monotonic()+3;responses=[]
    sockets={sender:'sender'}
    if receiver:sockets[receiver]='advertised_5060'
    while time.monotonic()<deadline:
        readable,_,_=select.select(list(sockets),[],[],max(0,deadline-time.monotonic()))
        if not readable:break
        for stream in readable:
            data,peer=stream.recvfrom(65535)
            if ('Call-ID: '+identifier).encode() not in data:continue
            responses.append(dict(socket=sockets[stream],local=stream.getsockname(),peer=peer,raw_base64=base64.b64encode(data).decode(),code=int(data.split(b' ',2)[1])))
        if source_port==5060 and responses:break
    print(json.dumps(dict(operation=operation,sender_local=local,sender_peer=sender.getpeername(),request_base64=base64.b64encode(request).decode(),responses=responses)))
finally:
    sender.close()
    if receiver:receiver.close()
