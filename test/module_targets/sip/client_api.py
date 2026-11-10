"""Real socket/SSL client controls against the owned Asterisk implementation."""
import base64
import hashlib
import json
import socket
import ssl
import sys
import urllib.request
import uuid


def encoded(data):
    return base64.b64encode(data).decode()


def parse(data):
    head, _, body = data.partition(b'\r\n\r\n')
    lines = head.decode().split('\r\n')
    version, code, reason = lines[0].split(' ', 2)
    assert version == 'SIP/2.0'
    headers = {}
    for line in lines[1:]:
        key, value = line.split(':', 1)
        headers.setdefault(key.lower(), []).append(value.strip())
    return dict(code=int(code), reason=reason, headers=headers, raw_base64=encoded(data))


def receive(stream, transport):
    if transport == 'udp':
        return stream.recv(65536)
    response = b''
    while b'\r\n\r\n' not in response:
        part = stream.recv(65536)
        if not part:
            raise EOFError('SIP peer closed before its headers')
        response += part
        assert len(response) < 65536
    header, _, body = response.partition(b'\r\n\r\n')
    length = int(next(line.split(b':', 1)[1] for line in header.split(b'\r\n') if line.lower().startswith(b'content-length:')))
    while len(body) < length:
        part = stream.recv(65536)
        if not part:
            raise EOFError('SIP peer closed before its body')
        response += part
        body += part
    return response


def sip(operation):
    transport = operation['transport']
    host, port = operation['host'], operation.get('port', 5061 if transport == 'tls' else 5060)
    raw = socket.socket(socket.AF_INET, socket.SOCK_DGRAM if transport == 'udp' else socket.SOCK_STREAM)
    raw.settimeout(operation.get('timeout', 3))
    stream = raw
    try:
        raw.connect((host, port))
        if transport == 'tls':
            trust = operation.get('trust', 'fixture')
            context = ssl.create_default_context(cafile='/etc/asterisk/module-target.pem' if trust == 'fixture' else None)
            stream = context.wrap_socket(raw, server_hostname='sip.module-target.test')
        local, peer = stream.getsockname(), stream.getpeername()
        account, method = operation['account'], operation['method']
        uri = 'sip:' + host if operation.get('wildcard') else 'sip:' + account + '@' + host
        identifier = uuid.uuid4().hex
        requests, responses = [], []
        authorization = None
        for sequence in [1, 2]:
            contact = '*' if operation.get('wildcard') else f'<sip:{account}@{local[0]}:5099;transport={transport}>'
            fields = [
                method + ' ' + uri + ' SIP/2.0',
                f'Via: SIP/2.0/{transport.upper()} {local[0]}:{local[1]};branch=z9hG4bK-{identifier}-{sequence};rport',
                f'From: {account} <sip:{account if operation.get("from_account") else "native-probe"}@{host if operation.get("from_account") else local[0]}>;tag={identifier}',
                f'To: {account} <sip:{account}@{host}>',
                f'Call-ID: {identifier}@{local[0]}',
                f'CSeq: {sequence} {method}',
                'Contact: ' + contact,
                'Expires: ' + str(operation.get('expires', 0)),
                'Max-Forwards: 70',
            ]
            if authorization:
                fields.append('Authorization: Digest ' + authorization)
            request = ('\r\n'.join(fields + ['Content-Length: 0', '', ''])).encode()
            stream.sendall(request)
            requests.append(encoded(request))
            response = parse(receive(stream, transport))
            responses.append(response)
            if sequence != 1 or response['code'] != 401 or operation.get('password') is None:
                break
            challenge = response['headers']['www-authenticate'][0]
            assert challenge.startswith('Digest ')
            values = urllib.request.parse_keqv_list(urllib.request.parse_http_list(challenge[7:]))
            assert values.get('algorithm', 'MD5').upper() == 'MD5' and 'qop' not in values
            md5 = lambda value: hashlib.md5(value.encode()).hexdigest()
            secret = md5(account + ':' + values['realm'] + ':' + operation['password'])
            result = md5(secret + ':' + values['nonce'] + ':' + md5(method + ':' + uri))
            authorization = f'username="{account}", realm="{values["realm"]}", nonce="{values["nonce"]}", uri="{uri}", response="{result}", algorithm=MD5'
        result = dict(local=local, peer=peer, socket_type=int(raw.type), requests=requests, responses=responses)
        if transport == 'tls':
            result.update(tls_version=stream.version(), cipher=stream.cipher(), peer_certificate_sha256=hashlib.sha256(stream.getpeercert(binary_form=True)).hexdigest())
        return result
    finally:
        stream.close()
        if stream is not raw:
            raw.close()


def ami(operation):
    def block(stream, delimiter):
        data = b''
        while delimiter not in data:
            part = stream.recv(65536)
            if not part:
                raise EOFError('AMI peer closed before its response')
            data += part
        return data

    with socket.create_connection((operation['host'], operation.get('port', 5038)), timeout=3) as stream:
        stream.settimeout(3)
        banner = block(stream, b'\r\n')
        request = ('Action: Login\r\nUsername: ' + operation['username'] + '\r\nSecret: ' + operation['password'] + '\r\nEvents: off\r\n\r\n').encode()
        stream.sendall(request)
        reply = block(stream, b'\r\n\r\n')
        result = dict(banner_base64=encoded(banner), login_request_base64=encoded(request), reply=reply.decode(), reply_base64=encoded(reply), commands=[])
        if reply.startswith(b'Response: Success\r\n'):
            for command in operation.get('commands', []):
                request = ('Action: Command\r\nCommand: ' + command + '\r\n\r\n').encode()
                stream.sendall(request)
                reply = block(stream, b'\r\n\r\n')
                result['commands'].append(dict(command=command, request_base64=encoded(request), reply_base64=encoded(reply), reply=reply.decode()))
        return result



def manager_state(operation):
    def fields(frame):
        return dict(line.split(': ', 1) if ': ' in line else (line.rstrip(':'), '') for line in frame.split('\r\n') if line)

    with socket.create_connection((operation['host'], operation.get('port', 5038)), timeout=3) as stream:
        stream.settimeout(3)
        reader = stream.makefile('rb')

        def frame():
            lines = []
            while True:
                line = reader.readline()
                if not line:
                    raise EOFError('AMI state peer closed before its frame')
                lines.append(line)
                if line == b'\r\n':
                    return b''.join(lines).decode()

        banner = reader.readline().decode()
        login = b'Action: Login\r\nUsername: module_manager\r\nSecret: module-target-manager-password\r\nEvents: off\r\n\r\n'
        stream.sendall(login)
        accepted = frame()
        assert fields(accepted).get('Response') == 'Success', accepted
        records, peers, registry = [], {}, {}
        for account in ['1000', '1001']:
            request = f'Action: SIPshowpeer\r\nPeer: {account}\r\nActionID: peer-{account}\r\n\r\n'
            stream.sendall(request.encode())
            reply = frame()
            data = fields(reply)
            assert data.get('Response') == 'Success' and data.get('ObjectName') == account, reply
            records.append(dict(request=request, frames=[reply]))
            peers[account] = dict(address=data['Address-IP'], port=int(data['Address-Port']), expiry=int(data['RegExpire'].split()[0]), historical_contact=data['Reg-Contact'], useragent=data['SIP-Useragent'])
            request = f'Action: DBGet\r\nFamily: SIP/Registry\r\nKey: {account}\r\nActionID: registry-{account}\r\n\r\n'
            stream.sendall(request.encode())
            reply = frame()
            data = fields(reply)
            frames = [reply]
            if data.get('Response') == 'Success':
                event = frame()
                frames.append(event)
                data = fields(event)
                assert data.get('Event') == 'DBGetResponse' and data.get('Key') == account, event
                registry[account] = data['Val']
                completed = frame()
                frames.append(completed)
                complete = fields(completed)
                assert complete.get('Event') == 'DBGetComplete' and int(complete.get('ListItems', '-1')) == 1, completed
            else:
                assert data.get('Response') == 'Error' and data.get('Message') == 'Database entry not found', reply
            records.append(dict(request=request, frames=frames))
        request = 'Action: CoreShowChannels\r\nActionID: channels\r\n\r\n'
        stream.sendall(request.encode())
        reply = frame()
        assert fields(reply).get('Response') == 'Success', reply
        frames, channels = [reply], []
        while True:
            reply = frame()
            frames.append(reply)
            data = fields(reply)
            if data.get('Event') == 'CoreShowChannelsComplete':
                assert int(data['ListItems']) == len(channels), reply
                break
            assert data.get('Event') == 'CoreShowChannel', reply
            channels.append({key: value for key, value in data.items() if key != 'ActionID'})
        records.append(dict(request=request, frames=frames))
        return dict(peers=peers, registry=registry, channels=channels, observation=dict(banner=banner, login=accepted, records=records))


if __name__ == '__main__':
    results = []
    for operation in json.load(sys.stdin):
        try:
            implementation = {'ami': ami, 'state': manager_state}.get(operation.get('api'), sip)
            result = implementation(operation)
        except (OSError, ValueError, EOFError, AssertionError) as error:
            result = dict(error_type=type(error).__name__, error=str(error))
        results.append(dict(operation=operation, result=result))
    print(json.dumps(results, indent=2))
