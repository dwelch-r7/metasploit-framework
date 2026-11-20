"""Calibrate the real auto-login/validation chain before interpreting owner output."""
from pathlib import Path
import base64
import importlib.util
import json
import os
import re
import sys

spec = importlib.util.spec_from_file_location('langflow_native', 'test/module_targets/langflow/native.py')
backend = importlib.util.module_from_spec(spec)
spec.loader.exec_module(backend)
tag = sys.argv[1]
assert re.fullmatch('[a-z0-9_-]+', tag)
enabled = os.environ['LANGFLOW_AUTO_LOGIN_EXPECT'] == 'true'
os.environ['LANGFLOW_PROFILE'] = 'default' if enabled else 'auth'
native = backend.Native('auto-login-' + tag)
record = {'checks': [], 'auto_login_expected': enabled, 'owner_qualified': False}


def check(name, passed):
    record['checks'].append({'name': name, 'passed': bool(passed)})
    if not passed:
        raise AssertionError(name)


def file_state(path):
    program = 'from pathlib import Path;import base64,json;p=Path(' + repr(path) + ');print(json.dumps(dict(exists=p.exists(),uid=p.stat().st_uid if p.exists() else None,base64=base64.b64encode(p.read_bytes()).decode() if p.exists() else None)))'
    return json.loads(native.execute('python', '-c', program))


def marker(token, label, expected_status):
    path = '/tmp/module-target-langflow-auto-native-' + tag + '-' + label
    content = 'langflow-auto-' + label + '-雪-\r\n'
    check('marker-absent-' + label, not file_state(path)['exists'])
    effect = '__import__("pathlib").Path(' + repr(path) + ').write_bytes(' + repr(content.encode()) + ')'
    # A default argument exercises the same vendor evaluator without copying
    # the owner's decorator or relying on its Python payload encoding.
    code = 'def module_target(value=' + effect + '):\n    return value\n'
    try:
        status, body = native.http('/api/v1/validate/code', token, data={'code': code})
        check('validation-status-' + label, status == expected_status)
        observed = file_state(path)
        if expected_status == 200:
            check('exact-native-proof-' + label, observed == {'exists': True, 'uid': 1000, 'base64': base64.b64encode(content.encode()).decode()})
        else:
            check('unauthorized-cannot-execute-' + label, not observed['exists'])
        record.setdefault('execution', []).append({'label': label, 'status': status, 'file': observed})
    finally:
        native.execute('rm', '-f', '--', path)
        check('marker-cleaned-' + label, not file_state(path)['exists'])


try:
    record['vendor'] = native.vendor()
    record['os_release'] = native.execute('cat', '/etc/os-release').decode()
    status, body = native.http('/api/v1/version')
    record['version'] = json.loads(body)
    check('real-langflow-version', status == 200 and record['version'].get('version') == '1.8.4' and record['version'].get('package') == 'Langflow')
    expected = json.loads(Path(__file__).with_name('sources.json').read_text())
    program = "import importlib.util,pathlib,hashlib,json;out={};files=" + repr(list(expected['sources'])) + ";exec('for name in files:\\n package,relative=name.split(\"/\",1);root=pathlib.Path(next(iter(importlib.util.find_spec(package).submodule_search_locations)));out[name]=hashlib.sha256((root/relative).read_bytes()).hexdigest()');print(json.dumps(out))"
    record['sources'] = json.loads(native.execute('python', '-c', program))
    check('installed-source-matches-pinned-upstream', record['sources'] == {name: row['sha256'] for name, row in expected['sources'].items()})
    record['settings'] = json.loads(native.execute('python', '-c', "import os,json;print(json.dumps({k:os.environ.get(k) for k in ['LANGFLOW_AUTO_LOGIN','LANGFLOW_SKIP_AUTH_AUTO_LOGIN']}))"))
    check('actual-authentication-settings', record['settings'] == {'LANGFLOW_AUTO_LOGIN': 'true' if enabled else 'false', 'LANGFLOW_SKIP_AUTH_AUTO_LOGIN': 'false'})
    status, body = native.http('/api/v1/auto_login')
    record['anonymous_auto_login_status'] = status
    check('auto-login-boundary', status == (200 if enabled else 403))
    anonymous_token = json.loads(body)['access_token'] if enabled else None
    if enabled:
        check('real-anonymous-token', isinstance(anonymous_token, str) and bool(anonymous_token))
    check('incorrect-password-rejected', native.http('/api/v1/login', form={'username': 'module-target-admin', 'password': 'module-target-incorrect'})[0] == 401)
    token = native.token()
    before = sorted(row['id'] for row in native.flows(token))
    record['flow_ids'] = before
    marker(None, 'unauthenticated', 403)
    marker(token, 'authenticated', 200)
    if enabled:
        marker(anonymous_token, 'anonymous-chain-first', 200)
        marker(anonymous_token, 'anonymous-chain-repeat', 200)
    check('flow-registry-preserved', sorted(row['id'] for row in native.flows(token)) == before)
    for filename in ['memory.events', 'pids.events']:
        fields = dict(row.split() for row in native.execute('cat', '/sys/fs/cgroup/' + filename).decode().splitlines())
        check('zero-resource-limit-events-' + filename, all(int(fields.get(k, '0')) == 0 for k in ['max', 'oom', 'oom_kill']))
    record['passed'] = True
finally:
    destination = native.artifacts / ('langflow-auto-native-' + tag + '.json')
    destination.write_text(json.dumps(record, indent=2) + '\n')
    print(json.dumps(record))
