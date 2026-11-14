"""Ordinary upstream s_server controls, independent of Framework."""
from pathlib import Path
import hashlib
import json
import socket
import ssl
import subprocess
import sys
from wire import buffering_control, heartbeat, providers as all_providers, root

providers = {name: row for name, row in all_providers.items() if row['kind'] == 'ordinary'}
after = sys.argv[1:] == ['after']
record = {'cases': [], 'providers': providers, 'status': 'running'}


def save():
    (root / 'ordinary-native.json').write_text(json.dumps(record, indent=2) + '\n')


def main():
    manifest = subprocess.run(['sha256sum', '-c', '/opt/openssl/binaries.sha256'], cwd='/opt/openssl', capture_output=True, text=True, check=True)
    record['binary_manifest'] = Path('/opt/openssl/binaries.sha256').read_text()
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    context.set_ciphers('AES128-SHA:@SECLEVEL=0')
    context.minimum_version = ssl.TLSVersion.TLSv1
    context.maximum_version = ssl.TLSVersion.TLSv1_2
    record['buffering_control'] = buffering_control(providers['affected-doc']['port'])
    for name, provider in providers.items():
        version = provider['version']
        provider['sdk'] = subprocess.check_output(['/opt/openssl/' + version + '/bin/openssl', 'version'], text=True).strip()
        provider['cmdline'] = (Path('/proc') / str(provider['pid']) / 'cmdline').read_bytes().replace(b'\0', b' ').decode()
        with socket.create_connection(('127.0.0.1', provider['port']), timeout=3) as raw:
            with context.wrap_socket(raw, server_hostname='heartbleed.invalid') as secure:
                provider['normal_tls'] = secure.version()
                provider['certificate_sha256'] = hashlib.sha256(secure.getpeercert(binary_form=True)).hexdigest()
        for protocol in ([0x0303] if after else [0x0301, 0x0302, 0x0303]):
            for valid in [True, False]:
                outcome = heartbeat(provider['port'], protocol, 8192, valid=valid)
                record['cases'].append({'name': name, 'tls_version': protocol, 'valid': valid, 'outcome': outcome})
                save()
                if name == 'disabled':
                    assert not outcome.get('received_payload_bytes'), outcome
                elif valid:
                    assert outcome.get('valid_echo'), outcome
                elif name == 'fixed':
                    assert not outcome.get('received_payload_bytes'), outcome
                else:
                    assert outcome.get('extra_bytes') == 8192, outcome
    record['ssl3_cases'] = []
    for name, provider in ([] if after else providers.items()):
        for valid in [True, False]:
            try:
                outcome = heartbeat(provider['port'], 0x0300, 8192, valid=valid)
            except (AssertionError, EOFError, OSError) as error:
                outcome = {'negotiation_error': repr(error)}
            record['ssl3_cases'].append({'name': name, 'valid': valid, 'outcome': outcome})
            if name == 'disabled' or (name == 'fixed' and not valid):
                assert not outcome.get('received_payload_bytes'), outcome
            elif valid:
                assert outcome.get('valid_echo'), outcome
            else:
                assert outcome.get('extra_bytes') == 8192, outcome
    record['status'] = 'passed'
    save()
    print(json.dumps(record))


if __name__ == '__main__':
    main()
