"""Independent Net-SNMP CLI controls; every write restores its original value."""
import json
import subprocess

CONTACT = '.1.3.6.1.2.1.1.4.0'
NAME = '.1.3.6.1.2.1.1.5.0'
DESCRIPTION = '.1.3.6.1.2.1.1.1.0'


def command(tool, version, community, transport, *arguments, success=True):
    argv = [tool, '-v' + version, '-c', community, '-t', '1', '-r', '0',
            '-Oqv', transport + ':127.0.0.1:161', *arguments]
    result = subprocess.run(argv, capture_output=True, text=True, timeout=5)
    records.append(dict(argv=argv, exitstatus=result.returncode,
                        stdout=result.stdout, stderr=result.stderr))
    if success and result.returncode != 0:
        raise RuntimeError(records[-1])
    return result


records = []
profiles = []
for version in ('1', '2c'):
    for transport in ('udp', 'tcp'):
        name = command('snmpget', version, 'public', transport, NAME).stdout.strip().strip('"')
        description = command('snmpget', version, 'public', transport, DESCRIPTION).stdout.strip().strip('"')
        original = command('snmpget', version, 'public', transport, CONTACT).stdout.strip().strip('"')
        marker = 'native-snmp-write-proof'
        try:
            command('snmpset', version, 'private', transport, CONTACT, 's', marker)
            changed = command('snmpget', version, 'public', transport, CONTACT).stdout.strip().strip('"')
            assert changed == marker, changed
            denied = command('snmpset', version, 'public', transport, CONTACT, 's', 'denied-change', success=False)
            assert denied.returncode != 0, denied.stdout
            assert command('snmpget', version, 'public', transport, CONTACT).stdout.strip().strip('"') == marker
        finally:
            command('snmpset', version, 'private', transport, CONTACT, 's', original)
        assert command('snmpget', version, 'public', transport, CONTACT).stdout.strip().strip('"') == original
        wrong = command('snmpget', version, 'wrong-community', transport, NAME, success=False)
        assert wrong.returncode != 0 and 'Timeout' in wrong.stderr, wrong.stderr
        profiles.append(dict(version=version, transport=transport, name=name,
                             description=description, contact=original))

print(json.dumps(dict(profiles=profiles, commands=records)))
