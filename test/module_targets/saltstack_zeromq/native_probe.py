"""Capture vendor-client, source, resource and reporting-database controls."""
import base64
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

runtime = json.loads(Path(sys.argv[1]).read_text())
version, phase = sys.argv[2:4]
source = Path(__file__).parent
configuration = json.loads((source / 'profiles.json').read_text())
commands = []
record = {'status': 'starting', 'phase': phase, 'commands': commands}


def execute(service, *argv, expected=0, stdin=None):
    result = subprocess.run(runtime['compose'] + ['exec', '-T', service, *argv],
                            input=stdin, capture_output=True, timeout=180)
    commands.append({'service': service, 'argv': argv, 'exitstatus': result.returncode,
                     'stdout_base64': base64.b64encode(result.stdout).decode(),
                     'stderr_base64': base64.b64encode(result.stderr).decode()})
    assert result.returncode == expected, commands[-1]
    return result.stdout


try:
    pg = ['psql', '-h', '127.0.0.1', '-U', 'module_framework', '-d', 'module_targets',
          '-v', 'ON_ERROR_STOP=1', '-Atc']
    record['postgres_version'] = execute('reporting_db', 'env',
        'PGPASSWORD=module-target-framework-db-password', *pg, 'SELECT version()').decode().strip()
    assert not execute('reporting_db', 'env', 'PGPASSWORD=module-target-rejected-password',
                       *pg, 'SELECT 1', expected=2)
    client = {'version': version, 'phase': phase,
              'vendor_files': configuration['packages'][version]['vendor_files'],
              'packages': {row['package']: row['version'] for row in configuration['runtime']}}
    acl = os.environ.get('SALT_ACL') == 'true'
    client['expected_users'] = ['bin', 'daemon', 'nobody', 'root'] if acl else ['root']
    files = {'/etc/salt/master': 'master-acl' if acl else 'master',
             '/etc/salt/minion': 'minion', '/opt/module-target/health.py': 'health.py'}
    client['fixture_files'] = {target: hashlib.sha256((source / name).read_bytes()).hexdigest()
                               for target, name in files.items()}
    output = execute('target', 'python', '-c', (source / 'native_client.py').read_text(),
                     stdin=json.dumps(client).encode())
    record['master'] = json.loads(output)
    assert record['master']['status'] == 'native_passed'
    record['resources'] = json.loads(execute('target', 'python', '-c',
        "import json,pathlib; print(json.dumps({name:pathlib.Path('/sys/fs/cgroup',name).read_text() "
        "for name in ['memory.events','pids.events','memory.max','memory.swap.max','cpu.max']}))"))
    for name in ['memory.events', 'pids.events']:
        assert all(int(line.split()[1]) == 0 for line in record['resources'][name].splitlines())
    assert record['resources']['memory.max'].strip() == str(320 * 1024**2)
    assert record['resources']['memory.swap.max'].strip() == '0'
    record['status'] = 'native_passed'
finally:
    path = Path(runtime['artifacts']) / ('native-' + phase + '.json')
    path.write_text(json.dumps(record, indent=2) + '\n')
    print(json.dumps({'status': record['status'], 'evidence': str(path)}))
