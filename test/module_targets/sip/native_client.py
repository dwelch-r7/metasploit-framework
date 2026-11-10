"""Execute genuine clients and preserve exact native command and wire evidence."""
import base64
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import subprocess
import time
import uuid


class NativeSIP:
    def __init__(self, runtime):
        self.runtime, self.commands = runtime, []
        self.artifacts = Path(runtime['artifacts'])
        self.addresses = {}
        self.context = uuid.uuid4().hex

    def process(self, argv, expected=0, stdin=None):
        try:
            result = subprocess.run(argv, input=stdin, capture_output=True, timeout=15)
            record = dict(argv=argv, exitstatus=result.returncode, stdout_base64=base64.b64encode(result.stdout).decode(), stderr_base64=base64.b64encode(result.stderr).decode())
        except subprocess.TimeoutExpired as error:
            record = dict(argv=argv, timeout=True, stdout_base64=base64.b64encode(error.stdout or b'').decode(), stderr_base64=base64.b64encode(error.stderr or b'').decode())
            self.commands.append(record)
            self.save()
            raise
        self.commands.append(record)
        self.save()
        assert expected is None or result.returncode == expected, record
        return result.stdout

    def command(self, service, *arguments, expected=0, stdin=None):
        return self.process(self.runtime['compose'] + ['exec', '-T', service] + list(arguments), expected, stdin)

    def save(self):
        self.commands[-1]['operation_context'] = self.context
        with (self.artifacts/'native-client-commands.jsonl').open('a') as output:
            output.write(json.dumps(self.commands[-1]) + '\n')
        (self.artifacts/'native-client-commands.json').write_text(json.dumps(self.commands, indent=2))

    def ip(self, service):
        if service not in self.addresses:
            identifier = self.process(self.runtime['compose'] + ['ps', '-q', service]).decode().strip()
            details = json.loads(self.process(['docker', 'inspect', identifier]))[0]
            networks = details['NetworkSettings']['Networks']
            assert len(networks) == 1
            self.addresses[service] = next(iter(networks.values()))['IPAddress']
        return self.addresses[service]

    def api(self, operations):
        return json.loads(self.command('client', 'python3', '/opt/module-target-client-api.py', stdin=json.dumps(operations).encode()))

    def wire(self, service, label):
        assert re.fullmatch(r'[A-Za-z0-9_-]+', label), label
        path = self.artifacts / (label + '-' + self.context + '.pcap')
        data = self.command(service, 'cat', '/tmp/module-target-sip.pcap')
        path.write_bytes(data)
        # Reuse the existing real Ethernet/IPv4 TCP reassembler unchanged.
        source = Path(__file__).resolve().parent.parent / 'capture_core' / 'native_client.py'
        specification = importlib.util.spec_from_file_location('module_target_capture_tcp', source)
        module = importlib.util.module_from_spec(specification)
        specification.loader.exec_module(module)
        result = dict(pcap=str(path), sha256=hashlib.sha256(data).hexdigest(), streams=module.tcp_streams(path))
        path.with_suffix('.wire.json').write_text(json.dumps(result, indent=2))
        return result

    def legacy_register(self, service, account, source_port=5060):
        source = Path(__file__).with_name('legacy_register.py').read_text()
        operation = dict(account=account, host=self.ip(service), source_port=source_port)
        return json.loads(self.command('client', 'python3', '-c', source, stdin=json.dumps(operation).encode()))

    def legacy_state(self, service):
        peers = {}
        for account in ['1000', '1001']:
            text = self.command(service, 'asterisk', '-rx', 'sip show peer ' + account).decode()
            address = re.search(r'^\s+Addr->IP\s*:\s*([^\r\n]+)', text, re.M)[1].strip()
            expiry = int(re.search(r'^\s+Expire\s*:\s*(-?\d+)', text, re.M)[1])
            peers[account] = dict(address=address, expiry=expiry)
        registry = self.command(service, 'asterisk', '-rx', 'database show SIP/Registry').decode().strip()
        channels = self.command(service, 'asterisk', '-rx', 'core show channels concise').decode().strip()
        return dict(peers=peers, registry=registry, channels=channels)

    def state(self, service):
        started = time.monotonic()
        row = self.api([dict(api='state', host=self.ip(service))])[0]
        finished = time.monotonic()
        assert 'error' not in row['result'], row
        result = row['result']
        peers = {account: {('remaining_seconds' if key == 'expiry' else key): value for key, value in peer.items()} for account, peer in result['peers'].items()}
        # Keep historical contacts visible; only observation timestamps are metadata.
        return dict(peers=peers, registry=result['registry'], channels=result['channels'], observed=dict(started=started, finished=finished))

    def inactive(self, service):
        state = self.state(service)
        assert all(row['address'] in ['(null)', '(Unspecified)'] and row['port'] == 0 and row['remaining_seconds'] == -1 for row in state['peers'].values()), state
        assert state['registry'] == {} and state['channels'] == [], state
        return state

    def unregister(self, service, account='1000'):
        before = self.state(service)
        peer = before['peers'][account]
        if peer['address'] in ['(null)', '(Unspecified)'] and peer['remaining_seconds'] == -1:
            return self.inactive(service)
        # This is explicit operator restoration, never attributed to the module.
        request = dict(host=self.ip(service), transport='udp', method='REGISTER', account=account, expires=0, wildcard=True, from_account=True)
        if account == '1001':
            request['password'] = 'module-target-sip-password'
        result = self.api([request])[0]
        assert 'error' not in result['result'] and result['result']['responses'][-1]['code'] == 200, result
        after = self.inactive(service)
        assert after['peers'][account]['historical_contact'] == peer['historical_contact'], (before, after)
        return after

    def sipsak(self, service, transport, account, password=None, expires=None, expected=None, symmetric=False):
        port = 5061 if transport == 'tls' else 5060
        argv = ['sipsak', '-vvv', '--timer-t1', '100', '--timeout-factor', '8', '--transport', transport]
        if symmetric:
            argv += ['--symmetric', '--local-port', '5099']
        if expires is not None:
            argv += ['-U', '-C', f'sip:{account}@{self.ip("client")}:5099;transport={transport}', '-x', str(expires)]
        if password is not None:
            argv += ['--auth-username', account, '-a', password]
        argv += ['-s', f'sip:{account}@{self.ip(service)}:{port}']
        before = len(self.commands)
        stdout = self.command('client', *argv, expected=expected)
        record = self.commands[before]
        stderr = base64.b64decode(record['stderr_base64'])
        return dict(exitstatus=record['exitstatus'], stdout_base64=record['stdout_base64'], stderr_base64=record['stderr_base64'], text=(stdout + stderr).decode(errors='replace'), codes=[int(code) for code in re.findall(rb'^SIP/2.0 (\d{3})', stdout + stderr, re.M)])

    def sipp(self, host, account='1001', expires=0, auth=True, response=200, transport='udp', password='module-target-sip-password', method='REGISTER'):
        # SIPp performs the digest calculation; these are client requests, never a target API.
        identifier = uuid.uuid4().hex
        prefix = '/tmp/module-target-sip-' + identifier
        request = '''REGISTER sip:[remote_ip] SIP/2.0
Via: SIP/2.0/[transport] [local_ip]:[local_port];branch=[branch];rport
From: ACCOUNT <sip:ACCOUNT@[remote_ip]>;tag=[call_number]
To: ACCOUNT <sip:ACCOUNT@[remote_ip]>
Call-ID: [call_id]
CSeq: SEQUENCE REGISTER
Contact: <sip:ACCOUNT@[local_ip]:[local_port];transport=[transport]>
Expires: EXPIRES
AUTHContent-Length: 0

'''
        request = request.replace('REGISTER', method)
        if method == 'OPTIONS':
            request = request.replace('OPTIONS sip:[remote_ip]', f'OPTIONS sip:{account}@[remote_ip]')
        steps = [(1, '', 401), (2, f'[authentication username={account} password={password}]\n', response)] if auth else [(1, '', response)]
        messages = []
        for sequence, authorization, code in steps:
            message = request.replace('ACCOUNT', account).replace('SEQUENCE', str(sequence)).replace('EXPIRES', str(expires)).replace('AUTH', authorization)
            messages.append('<send retrans="200"><![CDATA[\n' + message + ']]></send><recv response="' + str(code) + '" ' + ('auth="true" ' if auth and sequence == 1 else '') + 'timeout="2000"/>')
        scenario = '<?xml version="1.0"?><scenario name="owned-native-register">' + ''.join(messages) + '</scenario>'
        self.command('client', 'python3', '-c', 'import pathlib,sys;pathlib.Path(sys.argv[1]).write_bytes(sys.stdin.buffer.read())', prefix + '.xml', stdin=scenario.encode())
        try:
            auth_uri = ['-auth_uri', f'sip:{account}@{host}'] if method == 'OPTIONS' else []
            stdout = self.command('client', 'sipp', host + ':5060', '-sf', prefix + '.xml', '-i', self.ip('client'), '-p', '5098', '-t', 'u1' if transport == 'udp' else 't1', '-m', '1', '-l', '1', '-r', '1', '-nostdin', '-nd', '-trace_msg', '-message_file', prefix + '.messages', '-trace_err', '-error_file', prefix + '.errors', *auth_uri)
            trace = self.command('client', 'cat', prefix + '.messages')
            errors = self.command('client', 'python3', '-c', 'import pathlib,sys;p=pathlib.Path(sys.argv[1]);sys.stdout.buffer.write(p.read_bytes() if p.exists() else b"")', prefix + '.errors')
            assert not errors.strip(), errors
            codes = [int(code) for code in re.findall(rb'^SIP/2.0 (\d{3})', trace, re.M)]
            assert codes == [row[2] for row in steps], codes
            return dict(scenario=scenario, stdout_base64=base64.b64encode(stdout).decode(), trace_base64=base64.b64encode(trace).decode(), codes=codes)
        finally:
            self.command('client', 'python3', '-c', 'import pathlib,sys;[(pathlib.Path(sys.argv[1]+suffix).unlink(missing_ok=True)) for suffix in [".xml",".messages",".errors"]]', prefix)
