"""Independent real export wire, libnfs access and native probe restoration."""
import ipaddress
import json
import os
from pathlib import Path
import time
from native_client import NativeNFS

runtime = json.loads(Path(os.environ['MODULE_TARGET_RUNTIME']).read_text())
client = NativeNFS(runtime)
profiles = {}
started = time.monotonic()
try:
    for service in ['open', 'empty', 'unrelated']:
        identifier = client.process(runtime['compose'] + ['ps', '--quiet', service]).decode().strip()
        details = json.loads(client.process(['docker', 'inspect', identifier]))[0]
        assert details['HostConfig']['Privileged'] is False and details['HostConfig']['Init'] is True
        assert {value.removeprefix('CAP_') for value in details['HostConfig']['CapDrop']} >= {'SYS_ADMIN', 'SYS_TIME'}
        assert details['Mounts'] == []
        status = client.command(service, 'cat', '/proc/1/status').decode()
        cap = int(next(line for line in status.splitlines() if line.startswith('CapEff:')).split()[1], 16)
        assert cap & ((1 << 21) | (1 << 25)) == 0
        versions = client.command(service, 'dpkg-query', '-W', '-f', '${Package} ${Version}\n', 'rpcbind', 'netbase', 'libtirpc3', 'libnfs-utils').decode()
        protocols = client.command(service, 'cat', '/etc/protocols').decode()
        services = client.command(service, 'cat', '/etc/services').decode()
        fields = [line.split()[:2] for line in protocols.splitlines() if line and not line.startswith('#')]
        assert ['tcp', '6'] in fields and ['udp', '17'] in fields and 'sunrpc' in services
        cli = client.command('empty', 'rpcinfo', '-p', service).decode()
        cli_maps = []
        for line in cli.splitlines()[1:]:
            program, version, protocol, port, *_ = line.split()
            cli_maps.append([int(program), int(version), 6 if protocol == 'tcp' else 17, int(port)])
        rows = {}
        for protocol in ['tcp', 'udp']:
            maps = client.maps(service, protocol)
            assert maps == cli_maps and len(maps) == (6 if service == 'unrelated' else 12)
            rows[protocol] = dict(maps=maps)
            if service != 'unrelated':
                exports = client.exports(service, protocol)
                rows[protocol]['exports'] = exports
                assert len(exports) == (5 if service == 'open' else 0)
            client.command('empty', 'rpcinfo', '-t' if protocol == 'tcp' else '-u', service, '100000', '2')
        if service != 'unrelated':
            banner = client.command(service, '/usr/local/sbin/unfsd', '-h').decode()
            assert 'UNFS3 unfsd 0.11.0' in banner
            path = '/run/module-target.exports' if service == 'open' else '/etc/module-target/empty.exports'
            config = client.command(service, 'cat', path).decode()
            client.command(service, '/usr/local/sbin/unfsd', '-T', '-e', path)
            showmount = client.command('empty', 'showmount', '-e', service).decode()
        else:
            banner = config = showmount = ''
        profiles[service] = dict(transports=rows, versions=versions, banner=banner, config=config, showmount=showmount)
    address = client.command('open', 'ip', '-4', '-o', 'address', 'show', 'dev', 'eth0', 'scope', 'global').decode().split()[3]
    network = ipaddress.ip_interface(address).network
    exports = profiles['open']['transports']['tcp']['exports']
    assert exports == profiles['open']['transports']['udp']['exports']
    assert exports == [['/exports/open', ['<anon clnt>']], ['/exports/read-only', ['<anon clnt>']], ['/exports/denied', ['192.0.2.2/32']], ['/exports/network', [str(network)]], ['/exports/netmask', [f'{network.network_address}/{network.netmask}']]]
    baseline = client.filesystem()
    for repeat in range(2):
        for share, expected in [('open', 'public'), ('read-only', 'read-only'), ('network', 'network'), ('netmask', 'netmask')]:
            path = '/exports/' + share + '/proof.txt'
            assert client.command('empty', 'nfs-cat', 'nfs://open' + path) == ('module-target-nfs-' + expected + '\n').encode()
        client.command('empty', 'nfs-ls', 'nfs://open/exports/open/')
        client.command('empty', 'nfs-cat', 'nfs://open/exports/denied/proof.txt', expected=10)
        assert 'MNT3ERR_ACCES(13)' in client.commands[-1]['stderr']
        content = f'module-target-nfs-write-{repeat}\n'
        client.command('empty', 'python3', '-c', 'import pathlib,sys;pathlib.Path(sys.argv[1]).write_text(sys.argv[2])', '/tmp/module-target-nfs-input', content)
        name = f'native-write-{repeat}.txt'
        for share in ['open', 'network', 'netmask']:
            path = '/exports/' + share + '/' + name
            client.command('open', 'test', '!', '-e', path)
            client.command('empty', 'nfs-cp', '/tmp/module-target-nfs-input', 'nfs://open' + path)
            assert client.command('open', 'cat', path).decode() == content
            assert client.command('empty', 'nfs-cat', 'nfs://open' + path).decode() == content
            client.command('open', 'unlink', path)
            client.command('open', 'test', '!', '-e', path)
        path = '/exports/read-only/' + name
        client.command('empty', 'nfs-cp', '/tmp/module-target-nfs-input', 'nfs://open' + path, expected=10)
        assert 'NFS3ERR_ROFS(-30)' in client.commands[-1]['stderr']
        client.command('open', 'test', '!', '-e', path)
        assert client.filesystem() == baseline
    client.command('empty', 'unlink', '/tmp/module-target-nfs-input')
    assert client.filesystem() == baseline
    database = client.command('reporting_db', 'env', 'PGPASSWORD=module-target-framework-db-password', 'psql', '-h', '127.0.0.1', '-U', 'module_framework', '-d', 'module_targets', '-Atc', 'SELECT current_user,current_database(),version()').decode()
    assert database.startswith('module_framework|module_targets|PostgreSQL 16.')
    profiles['filesystem'] = baseline
    profiles['client_hostname'] = client.command('empty', 'hostname').decode().strip()
finally:
    client.write(Path(runtime['artifacts'])/'native-nfs-partial.json', profiles=profiles, seconds=time.monotonic()-started)
print(json.dumps(dict(commands=client.commands, requests=client.requests, profiles=profiles, seconds=time.monotonic()-started), indent=2))
