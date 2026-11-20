"""Prove the identical OS command through the real validator before the owner."""
import base64
import importlib.util
import json
import re
import sys

spec = importlib.util.spec_from_file_location('langflow_native', 'test/module_targets/langflow/native.py')
backend = importlib.util.module_from_spec(spec)
spec.loader.exec_module(backend)
label, path, encoded_command, encoded_expected = sys.argv[1:]
assert re.fullmatch('command-[01]', label)
assert re.fullmatch('/tmp/module-target-langflow-auto-owner-[0-9]+-[01]', path)
native = backend.Native('auto-login-' + label)
command = base64.b64decode(encoded_command, validate=True).decode()
expected = base64.b64decode(encoded_expected, validate=True)
native.execute('test', '!', '-e', path)
record = {'command_base64': encoded_command, 'expected_base64': encoded_expected}
try:
    token = native.token()
    effect = '__import__("subprocess").run(["/bin/sh","-c",' + repr(command) + '],check=True)'
    code = 'def module_target_native_command(value=' + effect + '):\n    return value\n'
    status, body = native.http('/api/v1/validate/code', token, data={'code': code})
    assert status == 200, (status, body)
    actual = native.execute('cat', path)
    uid = native.execute('stat', '-c', '%u', path).decode().strip()
    assert actual == expected and uid == '1000'
    record.update(passed=True, uid=1000, observed_base64=base64.b64encode(actual).decode())
finally:
    native.execute('rm', '-f', '--', path)
    native.execute('test', '!', '-e', path)
    record['proof_removed'] = True
    (native.artifacts / ('langflow-auto-native-' + label + '.json')).write_text(json.dumps(record, indent=2) + '\n')
    print(json.dumps(record))
