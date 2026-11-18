"""Draft OS environment controls; not yet executed in a native target."""
from pathlib import Path
import base64
import hashlib
import json
import os
import pwd
import subprocess
import sys

from env_values import environment_for

action = sys.argv[1]
assert action in ['control', 'process', 'case', 'restore']
case_file = Path('/run/module-target-env-case.json')


def environment_rows(raw):
    rows = [line.split(b'=', 1) for line in raw.split(b'\x00') if line]
    assert len(rows) == len({row[0] for row in rows}), 'Duplicate native variable names'
    return {key.decode(): value for key, value in rows}


if action in ['case', 'restore']:
    if action == 'case':
        variant = sys.argv[2]
        assert variant in ['standard', 'large'] and not case_file.exists()
        case_file.write_text(json.dumps({'variant': variant}) + '\n')
        case_file.chmod(0o644)
        print(json.dumps({'variant': variant, 'present': case_file.is_file()}))
    else:
        assert case_file.is_file()
        variant = sys.argv[2]
        assert variant in ['standard', 'large']
        assert json.loads(case_file.read_text()) == {'variant': variant}
        assert case_file.stat().st_uid == 0
        assert case_file.stat().st_mode & 0o777 == 0o644
        case_file.unlink()
        print(json.dumps({'absent': not case_file.exists()}))
    raise SystemExit(0)

if action == 'control':
    user, variant = sys.argv[2:4]
    account = pwd.getpwnam(user)
    expected = environment_for(user, variant)
    observed_uid = subprocess.check_output(['/usr/bin/id', '-u'], env=expected,
                                           user=account.pw_uid, group=account.pw_gid, extra_groups=[])
    assert int(observed_uid) == account.pw_uid
    process = subprocess.Popen(['/usr/bin/env', '-0'], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               env=expected, user=account.pw_uid, group=account.pw_gid, extra_groups=[])
    output, error = process.communicate(timeout=10)
    assert process.returncode == 0 and error == b''
    actual = environment_rows(output)
    assert actual == {key: value.encode() for key, value in expected.items()}
    assert not Path('/proc', str(process.pid)).exists()
    packages = subprocess.check_output(['dpkg-query', '-W', '-f=${Package}=${Version}\n', 'coreutils', 'python3'], text=True)
    print(json.dumps({'native_passed': True, 'user': user, 'uid': int(observed_uid), 'variant': variant,
                      'argv': ['/usr/bin/env', '-0'], 'exit': process.returncode, 'process_absent': True,
                      'observed_base64': {key: base64.b64encode(value).decode() for key, value in actual.items()},
                      'stdout_sha256': hashlib.sha256(output).hexdigest(), 'stdout_bytes': len(output),
                      'packages': packages, 'binary_sha256': hashlib.sha256(Path('/usr/bin/env').read_bytes()).hexdigest()}))
else:
    pid = int(sys.argv[2])
    user, variant = sys.argv[3:5]
    # Read the recorded process as its actual user, without adding ptrace caps.
    account = pwd.getpwnam(user)
    if os.geteuid() != account.pw_uid:
        assert os.geteuid() == 0
        os.setgroups([])
        os.setgid(account.pw_gid)
        os.setuid(account.pw_uid)
    process = Path('/proc', str(pid))
    status = dict(line.split(':', 1) for line in (process / 'status').read_text().splitlines())
    assert int(status['Uid'].split()[1]) == pwd.getpwnam(user).pw_uid
    assert status['State'].strip().split()[0] != 'Z'
    actual = environment_rows((process / 'environ').read_bytes())
    expected = environment_for(user, variant)
    assert all(actual[key] == value.encode() for key, value in expected.items())
    print(json.dumps({'native_passed': True, 'pid': pid, 'user': user, 'variant': variant,
                      'uid': int(status['Uid'].split()[1]), 'state': status['State'].strip(),
                      'expected_variable_count': len(expected),
                      'selected_base64': {key: base64.b64encode(actual[key]).decode() for key in expected}}))
