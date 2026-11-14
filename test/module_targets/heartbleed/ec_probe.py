"""Validate an actual ECDSA certificate and real non-RSA heartbeat exposure."""
from pathlib import Path
import hashlib
import json
import socket
import ssl
import subprocess

from wire import heartbeat, root

record = {'status': 'running', 'cases': []}
try:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    context.set_ciphers('ECDHE-ECDSA-AES128-SHA:@SECLEVEL=0')
    with socket.create_connection(('127.0.0.1', 12000), timeout=3) as raw:
        with context.wrap_socket(raw, server_hostname='heartbleed-ec.invalid') as secure:
            record['normal_tls'] = secure.version()
            record['certificate_sha256'] = hashlib.sha256(secure.getpeercert(binary_form=True)).hexdigest()
    certificate = subprocess.check_output(['openssl', 'x509', '-in', str(root / 'ec-cert.pem'), '-noout', '-text'], text=True)
    assert 'Public Key Algorithm: id-ecPublicKey' in certificate
    record['certificate_algorithm'] = 'id-ecPublicKey'
    for valid in [True, False]:
        outcome = heartbeat(12000, 0x0303, 8192, valid=valid, ciphers=b'\xc0\x09')
        record['cases'].append({'valid': valid, 'outcome': outcome})
        assert outcome.get('valid_echo') if valid else outcome.get('extra_bytes') == 8192
    record['status'] = 'passed'
finally:
    (root / 'ec-native.json').write_text(json.dumps(record, indent=2) + '\n')
print(json.dumps(record))
