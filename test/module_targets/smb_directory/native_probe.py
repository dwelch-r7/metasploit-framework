"""Real Samba client controls; no Framework implementation is imported."""
import base64
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parent
runtime = json.loads(Path(os.environ['MODULE_TARGET_RUNTIME']).read_text())
profile = sys.argv[1]
commands = []
started = time.monotonic()


def run(service, *arguments, expected=0, stdin=None, timeout=15):
    argv = (runtime['compose'] + ['exec', '-T', service] if service else []) + list(arguments)
    begin = time.monotonic()
    result = subprocess.run(argv, input=stdin, capture_output=True, timeout=timeout)
    commands.append(dict(argv=argv, exitstatus=result.returncode, seconds=time.monotonic()-begin,
                         stdout_base64=base64.b64encode(result.stdout).decode(),
                         stderr_base64=base64.b64encode(result.stderr).decode()))
    Path(runtime['artifacts'], 'native-smb-partial.json').write_text(json.dumps(commands, indent=2))
    assert result.returncode == expected, commands[-1]
    return result.stdout


def rpc(command, user='rpc_admin', expected=0, debug=False):
    password = credentials[user]
    return run('client', 'rpcclient', '--configfile=/opt/module-target-client.conf',
               '-d', '10' if debug else '0', '-U', user+'%'+password, 'samba', '-c', command, expected=expected)


def read(share, path, user='directory_reader', password=None, expected=0):
    return run('client', 'smbclient', '--configfile=/opt/module-target-client.conf', '//samba/'+share,
               '-U', user+'%'+(credentials[user] if password is None else password),
               '-c', 'get '+path+' /dev/stdout', expected=expected)


credentials = json.loads((ROOT/'credentials.json').read_text())
data = {}
data['versions'] = run('samba', 'dpkg-query', '-W', '-f', '${Package} ${Version}\n', 'samba', 'smbclient', 'openssl').decode()
assert 'samba 2:4.15.13+' in data['versions']
data['configuration'] = run('samba', 'testparm', '-s').decode()
assert 'server role = standalone server' in data['configuration']
assert 'S-1-5-32-544' in run('samba', 'net', 'groupmap', 'list').decode()
assert 'directory_admins' in run('samba', 'id', 'rpc_admin').decode()
assert read('SESSION', 'account-proof.txt') == b'Module target native policy account proof\n'
for dialect in ['NT1', 'SMB2']:
    proof = run('client', 'smbclient', '--configfile=/opt/module-target-client.conf', '//samba/SESSION',
                '-m', dialect, '--option=client min protocol='+dialect,
                '-U', 'directory_reader%'+credentials['directory_reader'], '-c', 'get account-proof.txt /dev/stdout')
    assert proof == b'Module target native policy account proof\n'
assert b'NT_STATUS_LOGON_FAILURE' in read('SESSION', 'account-proof.txt', password='public-wrong-password', expected=1)
assert b'NT_STATUS_LOGON_FAILURE' in read('SESSION', 'account-proof.txt', user='not_a_fixture_account', password='public-wrong-password', expected=1)
status = run('samba', 'cat', '/proc/1/status').decode()
caps = int(next(line.split()[1] for line in status.splitlines() if line.startswith('CapEff:')), 16)
assert not caps & (1 << 21 | 1 << 25)
assert not rpc('wkssvc_enumerateusers 1').strip()
assert b'WERR_ACCESS_DENIED' in rpc('wkssvc_enumerateusers 1', user='directory_reader', expected=1)
data['server_info'] = rpc('wkssvc_wkstagetinfo 100', debug=True).decode()

if profile == 'gpp':
    key = '4e9906e8fcb66cc9faf49310620ffee8f496e806cc057990209b09a433b66c1b'
    data['files'] = []
    for item in json.loads((ROOT/'policies.json').read_text())['files']:
        raw = read('SYSVOL', item['path'])
        assert len(raw) == item['bytes'] and hashlib.sha256(raw).hexdigest() == item['sha256']
        attributes = ET.fromstring(raw).find('.//Properties').attrib
        encoded = attributes['cpassword']
        encrypted = base64.b64decode(encoded+'='*((-len(encoded)) % 4))
        plaintext = run(None, 'openssl', 'enc', '-aes-256-cbc', '-d', '-nosalt', '-K', key,
                        '-iv', '0'*32, stdin=encrypted).decode('utf-16-le')
        assert plaintext == item['password']
        user = next(attributes[name] for name in ['userName', 'username', 'runAs', 'accountName'] if name in attributes)
        assert user == item['reported_user']
        assert read('SESSION', 'account-proof.txt', user=user, password=plaintext) == b'Module target native policy account proof\n'
        data['files'].append(dict(path=item['path'], sha256=item['sha256'], user=user, password=plaintext, authenticated=True))
    for share in ['EMPTY', 'EMPTY_POLICIES']:
        data[share] = run('client', 'smbclient', '--configfile=/opt/module-target-client.conf', '//samba/'+share,
                          '-U', 'directory_reader%'+credentials['directory_reader'], '-c', 'ls').decode()
    denied = run('client', 'smbclient', '--configfile=/opt/module-target-client.conf', '//samba/PROTECTED',
                 '-U', 'directory_reader%'+credentials['directory_reader'], '-c', 'ls', expected=1)
    assert b'NT_STATUS_ACCESS_DENIED' in denied

if profile == 'pipes':
    # The complete original module list is an input, not a shortened success list.
    pairs = json.loads((ROOT/'pipe_uuids.json').read_text())
    code = (ROOT/'pipe_bindings.py').read_text()
    rows = json.loads(run('client', 'python3', '-c', code, stdin=json.dumps(pairs).encode(), timeout=45))
    assert len(rows) == 3 * len(pairs)
    data['bindings'] = rows
    expected = [['12345778-1234-abcd-ef00-0123456789ac', '1.0'], ['afa8bd80-7d8a-11c9-bef4-08002b102989', '1.0']]
    assert [[r['uuid'], r['version']] for r in rows if r['status']=='OPEN'] == expected
    assert {r['pipe'] for r in rows if r['status']=='OPEN'} == {'samr'}
    for row in rows:
        if row['status'] == 'ERROR':
            # Native Python NTSTATUS: absent pipe vs bind interface rejection.
            expected_status = 0xc0020026 if row['pipe'] == 'samr' else 0xc0000034
            assert row['error'] == 'NTSTATUSError' and row['args'][0] == expected_status, row

assert not rpc('wkssvc_enumerateusers 1').strip()
print(json.dumps(dict(profile=profile, data=data, commands=commands, seconds=time.monotonic()-started), indent=2, ensure_ascii=False))
