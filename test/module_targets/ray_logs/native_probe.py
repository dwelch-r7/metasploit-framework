"""Verify native log API behavior independently of Framework."""
import base64
import json
import posixpath
from pathlib import Path
import subprocess
import sys
import traceback
import urllib.parse
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'ray'))
from native_probe import NativeRay

runtime = json.loads(Path(sys.argv[1]).read_text())
artifacts = Path(runtime['artifacts'])
native = NativeRay(runtime)
result = {'status': 'native_failed', 'owned_state_restored': False, 'framework_calls': 0}
fixture = None
commands = []
def target(action, **values):
    source = Path(__file__).with_name('native_target.py').read_text()
    argv = runtime['compose'] + ['exec', '-T', 'ray', 'python', '-c', source, json.dumps(dict(action=action, **values))]
    row = {'argv': argv}
    commands.append(row)
    value = subprocess.run(argv, capture_output=True, text=True, timeout=120)
    row.update(stdout=value.stdout, stderr=value.stderr, exitstatus=value.returncode)
    assert value.returncode == 0, row
    lines = [line.split(':', 1)[1] for line in value.stdout.splitlines() if line.startswith('MODULE_TARGET_RAY_LOGS_JSON:')]
    assert len(lines) == 1
    return json.loads(lines[0])

try:
    manifest = runtime['source_manifest']
    identity = native.target('identity', files=list(manifest['files']))
    result['identity'] = identity
    assert identity['version'] == manifest['version'] and identity['commit'] == manifest['commit'] and identity['uid'] == 1000
    for name, expected in manifest['files'].items():
        assert identity['sources'][name]['sha256'] == expected['sha256'], name
    core = native.target('core', nonce=uuid.uuid4().hex)
    result['core'] = core
    assert core['task']['value'] == 42 and core['task']['uid'] == 1000
    fixture = target('seed', nonce=uuid.uuid4().hex, node_id=core['nodes'][0]['NodeID'])
    result['fixture'] = fixture
    assert fixture['uid'] == 1000 and fixture['gid'] == 100
    result['sdk'] = target('sdk', fixture=fixture, policy=manifest['policy'])
    for name, item in fixture['patterns'].items():
        path = '/api/v0/logs?' + urllib.parse.urlencode({'node_id': fixture['node_id'], 'glob': item['glob'], 'timeout': 10})
        status, raw = native.request('head', path)
        if manifest['policy'] == 'confined' and name != 'ordinary':
            assert status == 500, (name, status, raw)
        else:
            assert status == 200, (name, status, raw)
            payload = json.loads(raw)
            assert payload['result'] is True
            groups = payload['data']['result']
            assert isinstance(groups, dict)
            entries = groups.get('internal', [])
            assert isinstance(entries, list)
            canonical = sorted(posixpath.normpath(fixture['log_dir'] + '/' + entry.rstrip('/')) + ('/' if entry.endswith('/') else '') for entry in entries)
            assert canonical == sorted(item['expected']), (name, entries, canonical)
    if manifest['policy'] == 'confined':
        absolute = str(Path(fixture['root']) / 'outside/plain.txt')
        path = '/api/v0/logs?' + urllib.parse.urlencode({'node_id': fixture['node_id'], 'glob': absolute, 'timeout': 10})
        status, raw = native.request('head', path)
        assert status == 500, (status, raw)
        result['http_denials'] = target('http_denials', fixture=fixture)
    status, raw = native.request('head', '/api/cluster_status')
    assert status == 200 and fixture['node_id'].encode() in raw
    status, raw = native.request('unrelated', '/api/v0/logs')
    assert status == 404
    result['fixture_verification'] = target('verify', fixture=fixture)
    result['cleanup'] = target('cleanup', fixture=fixture)
    fixture = None
    result['owned_state_restored'] = True
    result['status'] = 'native_passed'
except Exception as error:
    result['error'] = {'class': type(error).__name__, 'message': str(error)}
    result['traceback'] = traceback.format_exc()
finally:
    if fixture:
        try:
            result['failure_cleanup'] = target('cleanup', fixture=fixture)
        except Exception as error:
            result['cleanup_error'] = str(error)
    (artifacts / 'native-result.json').write_text(json.dumps(result, indent=2) + '\n')
    (artifacts / 'native-observations.json').write_text(json.dumps({'base_commands': native.commands, 'log_commands': commands, 'requests': native.requests}, indent=2) + '\n')
print(json.dumps({'status': result['status'], 'error': result.get('error')}))
raise SystemExit(0 if result['status'] == 'native_passed' else 1)
