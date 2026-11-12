"""Run independent Salt collection controls and inspect the reporting database."""
import base64
import json
from pathlib import Path
import subprocess
import sys

runtime = json.loads(Path(sys.argv[1]).read_text())
phase = sys.argv[2]
source = Path(__file__).parent
pins = json.loads((source.parent / 'saltstack_zeromq/profiles.json').read_text())
gather = json.loads((source / 'vendor-files.json').read_text())
system = json.loads((source / 'system-package.json').read_text())
extra = json.loads((source.parent / 'saltstack_rce/vendor-files.json').read_text())
record = {'status': 'starting', 'phase': phase, 'commands': []}


def execute(service, *argv, expected=0, stdin=None):
    result = subprocess.run(runtime['compose'] + ['exec', '-T', service, *argv],
                            input=stdin, capture_output=True, timeout=240)
    entry = {'service': service, 'argv': argv, 'exitstatus': result.returncode,
             'stdout_base64': base64.b64encode(result.stdout).decode(),
             'stderr_base64': base64.b64encode(result.stderr).decode()}
    record['commands'].append(entry)
    assert result.returncode == expected, entry
    return result.stdout


try:
    pg = ['psql', '-h', '127.0.0.1', '-U', 'module_framework', '-d', 'module_targets',
          '-v', 'ON_ERROR_STOP=1', '-Atc']
    record['postgres_version'] = execute('reporting_db', 'env',
        'PGPASSWORD=module-target-framework-db-password', *pg, 'SELECT version()').decode().strip()
    assert not execute('reporting_db', 'env', 'PGPASSWORD=module-target-rejected-password',
                       *pg, 'SELECT 1', expected=2)
    configuration = {
        'vendor_files': dict(pins['packages']['3000.1']['vendor_files'], **extra['extra_vendor_files'], **gather['vendor_files']),
        'system_package': system,
        'packages': {row['package']: row['version'] for row in pins['runtime']},
    }
    raw = execute('target', 'python', '-c', (source / 'native_client.py').read_text(),
                  stdin=json.dumps(configuration).encode())
    prefix = 'SALT_GATHER_NATIVE='
    lines = [line[len(prefix):] for line in raw.decode().splitlines() if line.startswith(prefix)]
    assert len(lines) == 1
    record['cluster'] = json.loads(lines[0])
    assert record['cluster']['status'] == 'native_passed'
    record['status'] = 'native_passed'
finally:
    path = Path(runtime['artifacts']) / ('native-' + phase + '.json')
    path.write_text(json.dumps(record, indent=2) + '\n')
    print(json.dumps({'status': record['status'], 'evidence': str(path)}))
