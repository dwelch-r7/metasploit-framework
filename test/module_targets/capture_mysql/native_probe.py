"""Prove selected genuine client/server pairs and actual challenge-response bytes."""
import base64
import hashlib
import json
import os
from pathlib import Path
import sys

sys.dont_write_bytecode = True
sys.path.insert(0, 'test/module_targets/database_capture')
from controls import ACCOUNTS, NativeClients, mysql_accounts, mysql_arguments, mysql_seed, mysql_wire

CLIENTS = {'oracle_client': '8.0.36', 'mariadb_client': '11.2.2'}
SERVERS = {'native_mysql': '8.0.36', 'native_mariadb': '11.2.2'}


def selection(name, available):
    value = os.environ.get(name, 'all')
    if value == 'all':
        return list(available)
    if value not in available:
        raise ValueError('Unknown native selection: ' + name + '=' + value)
    return [value]


def probe(phase):
    clients = NativeClients()
    roles = selection('MYSQL_CAPTURE_CLIENT', CLIENTS)
    servers = selection('MYSQL_CAPTURE_SERVER', SERVERS)
    identity = clients.command('client', 'python3', '/opt/module-target-client.py', 'identity')
    assert identity['status'] == 0, identity
    client_ip = json.loads(identity['stdout'])['client_ip']
    state = {'clients': {}, 'servers': {}}
    for role in roles:
        result = clients.command(role, 'mysql' if role == 'oracle_client' else 'mariadb', '--version')
        assert result['status'] == 0 and CLIENTS[role] in result['stdout'], result
        state['clients'][role] = result['stdout']
    proofs = []
    for service in servers:
        version = SERVERS[service]
        if phase == 'before':
            fixture = mysql_seed(clients, service)
        else:
            fixture = mysql_accounts()
        for role in roles:
            for kind, user, password in fixture:
                label = '-'.join(['native', phase, service, role, kind])
                result = clients.capture(label, 3306, role, *mysql_arguments(role, service, 3306, user, password, ACCOUNTS['database']))
                assert result['status'] == 0, result
                assert user + '@%\t' + ACCOUNTS['database'] + '\t' + version in result['stdout'], result
                decoded = mysql_wire(json.loads((clients.artifacts / (label + '.wire.json')).read_text()), client_ip, password)
                assert decoded['login']['username'] == user and decoded['login']['database'] == ACCOUNTS['database'], decoded
                if not password:
                    assert decoded['native_response'] == '', decoded
                proofs.append({'label': label, **decoded})
            label = '-'.join(['native', phase, service, role, 'rejected'])
            result = clients.capture(label, 3306, role, *mysql_arguments(role, service, 3306, ACCOUNTS['username'], ACCOUNTS['rejected_password'], ACCOUNTS['database']))
            assert result['status'] != 0 and '1045' in result['stderr'], result
            decoded = mysql_wire(json.loads((clients.artifacts / (label + '.wire.json')).read_text()), client_ip, ACCOUNTS['rejected_password'])
            proofs.append({'label': label, **decoded})
            label = '-'.join(['native', phase, service, role, 'default-tls'])
            result = clients.capture(label, 3306, role, *mysql_arguments(role, service, 3306, ACCOUNTS['username'], ACCOUNTS['password'], ACCOUNTS['database'], default_tls=True))
            assert result['status'] == 0 and ACCOUNTS['username'] + '@%\t' + ACCOUNTS['database'] + '\t' + version in result['stdout'], result
            streams = json.loads((clients.artifacts / (label + '.wire.json')).read_text())
            outgoing = base64.b64decode(next(stream['base64'] for stream in streams if stream['source'] == client_ip))
            length = int.from_bytes(outgoing[:3], 'little')
            flags = int.from_bytes(outgoing[4:8], 'little')
            if flags & 0x800:
                assert length == 32 and outgoing[4 + length:5 + length] == b'\x16', outgoing.hex()
                proofs.append({'label': label, 'default_tls': 'SSLRequest and real TLS records; native SQL identity succeeded', 'client_flags': flags})
            else:
                proofs.append({'label': label, 'default_tls': 'Client elected plaintext', **mysql_wire(streams, client_ip, ACCOUNTS['password'])})
        label = '-'.join(['native', phase, service, 'greeting-only'])
        greeting = clients.capture(label, 3306, 'client', 'python3', '/opt/module-target-database-client.py', 'greeting', '--host', service, '--port', '3306')
        assert greeting['status'] == 0 and json.loads(greeting['stdout'])['greeting_hex'][8:10] == '0a', greeting
        binary = 'mysql' if service == 'native_mysql' else 'mariadb'
        snapshot = clients.command(service, binary, '-uroot', '-ppassword', '--batch', '--skip-column-names', '--execute=SELECT user,host,plugin,authentication_string FROM mysql.user WHERE user LIKE \'capture%\' ORDER BY user,host')
        assert snapshot['status'] == 0 and len(snapshot['stdout'].splitlines()) == 4, snapshot
        state['servers'][service] = {'version': version, 'accounts_sha256': hashlib.sha256(snapshot['stdout_base64'].encode()).hexdigest()}
    schema = clients.command('reporting_db', 'env', 'PGPASSWORD=module-target-framework-db-password', 'psql', '-h', '127.0.0.1', '-U', 'module_framework', '-d', 'module_targets', '-Atc', "SELECT count(*) FROM information_schema.tables WHERE table_schema='public'")
    assert schema['status'] == 0, schema
    assert int(schema['stdout'].strip()) == 0 if phase == 'before' else int(schema['stdout'].strip()) > 0
    native_seed = next(proof['native_challenge'] for proof in proofs if 'native_challenge' in proof)
    assert len(bytes.fromhex(native_seed)) == 20
    output = {'client_ip': client_ip, 'clients': roles, 'servers': servers, 'state': state,
              'commands': clients.commands, 'wire_captures': sorted(path.name for path in clients.artifacts.glob('native-' + phase + '-*.pcap')),
              'proofs': proofs, 'native_challenge': native_seed, 'native_seed_has_nul': b'\x00' in bytes.fromhex(native_seed),
              'server_version': SERVERS[servers[0]]}
    (clients.artifacts / ('native-mysql-' + phase + '.json')).write_text(json.dumps(output, indent=2) + '\n')
    return output


if __name__ == '__main__':
    phase = sys.argv[1] if len(sys.argv) == 2 else 'before'
    if phase not in ('before', 'after'):
        raise ValueError('Unknown native phase')
    print(json.dumps(probe(phase)))
