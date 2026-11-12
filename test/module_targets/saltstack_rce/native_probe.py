"""Verify the genuine cluster and disposable reporting database independently."""
import base64
import hashlib
import json
from pathlib import Path
import subprocess
import sys

runtime = json.loads(Path(sys.argv[1]).read_text())
phase = sys.argv[2]
source = Path(__file__).parent
base = source.parent / 'saltstack_zeromq'
configuration = json.loads((base / 'profiles.json').read_text())
extra = json.loads((source / 'vendor-files.json').read_text())
commands = []
record = {'status': 'starting', 'phase': phase, 'commands': commands}


def execute(service, *argv, expected=0, stdin=None):
    result = subprocess.run(runtime['compose'] + ['exec', '-T', service, *argv],
                            input=stdin, capture_output=True, timeout=240)
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
    files = {'/etc/salt/master': source / 'master',
             '/opt/module-target/minion-template': source / 'minion',
             '/opt/module-target/session-target.py': source / 'session-target.py',
             '/opt/module-target/health.py': base / 'health.py'}
    vendor = dict(configuration['packages']['3000.1']['vendor_files'], **extra['extra_vendor_files'])
    client = {'version': '3000.1', 'vendor_files': vendor,
              'packages': {row['package']: row['version'] for row in configuration['runtime']},
              'fixture_files': {name: hashlib.sha256(path.read_bytes()).hexdigest() for name, path in files.items()}}
    raw = execute('target', 'python', '-c', (source / 'native_client.py').read_text(),
                  stdin=json.dumps(client).encode())
    lines = raw.decode().splitlines()
    records = [line.split('=', 1)[1] for line in lines if line.startswith('SALT_NATIVE_RECORD=')]
    assert len(records) == 1
    record['cluster'] = json.loads(records[0])
    assert record['cluster']['status'] == 'native_passed'
    record['status'] = 'native_passed'
finally:
    path = Path(runtime['artifacts']) / ('native-' + phase + '.json')
    path.write_text(json.dumps(record, indent=2) + '\n')
    print(json.dumps({'status': record['status'], 'evidence': str(path)}))
