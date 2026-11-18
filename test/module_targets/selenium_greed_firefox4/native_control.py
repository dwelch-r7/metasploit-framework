from pathlib import Path
import base64
import hashlib
import http.client
import io
import json
import subprocess
import sys
import time
import zipfile

runtime = json.loads(Path(sys.argv[1]).read_text())
out = Path(runtime['directory'])
legacy = runtime['profile']['version'].startswith('3.')
api = '/wd/hub' if legacy else ''
record = {'passed': False, 'owner_calls': 0, 'requests': [], 'commands': []}
active = None
root = '/tmp/module-target-selenium-native-' + runtime['stamp']
marker = root + '/handler-proof'
expected = b'native-handler\n'

def save():
    (out / 'native.json').write_text(json.dumps(record, indent=2) + '\n')

def command(label, *argv, required=True):
    p = subprocess.run(runtime['compose'] + ['exec', '-T', 'target', *argv], capture_output=True, timeout=30)
    record['commands'].append({'label': label, 'argv': argv, 'exit': p.returncode, 'stdout_base64': base64.b64encode(p.stdout).decode(), 'stderr_base64': base64.b64encode(p.stderr).decode()})
    save()
    if required:
        assert p.returncode == 0, (label, p.stderr.decode(errors='replace'))
    return p

def request(method, path, payload=None, json_response=True):
    connection = http.client.HTTPConnection('127.0.0.1', runtime['port'], timeout=60)
    started = time.monotonic()
    try:
        connection.request(method, path, body=None if payload is None else json.dumps(payload), headers={'Content-Type': 'application/json', 'Connection': 'close'})
        response = connection.getresponse()
        raw = response.read()
        row = {'method': method, 'path': path, 'payload': payload, 'status': response.status, 'body_base64': base64.b64encode(raw).decode(), 'seconds': time.monotonic() - started}
        record['requests'].append(row)
        save()
        return response.status, json.loads(raw) if json_response else raw
    except BaseException as error:
        record['requests'].append({'method': method, 'path': path, 'payload': payload, 'error': type(error).__name__, 'message': str(error), 'seconds': time.monotonic() - started})
        save()
        raise
    finally:
        connection.close()

def ok(method, path, payload=None):
    status, data = request(method, path, payload)
    assert status == 200, record['requests'][-1]
    return data['value']

def sessions():
    if legacy:
        status = ok('GET', api + '/status')
        assert status['build']['version'] == runtime['profile']['version']
        return [row['id'] for row in ok('GET', api + '/sessions')], status
    status = ok('GET', '/status')
    assert len(status['nodes']) == 1
    node = status['nodes'][0]
    assert node['version'].startswith(runtime['profile']['version'] + ' ')
    assert {row['stereotype']['browserName'] for row in node['slots']} == {'firefox'}
    return [row['session']['sessionId'] for row in node['slots'] if row['session']], status

try:
    deadline = time.monotonic() + 150
    while True:
        try:
            ids, status = sessions()
            if status['ready']:
                break
        except (OSError, AssertionError, KeyError, ValueError):
            pass
        assert time.monotonic() < deadline, 'Grid readiness timeout'
        time.sleep(1)
    assert ids == []
    record['initial_status'] = status
    if legacy:
        for path in ['/', '/status', api + '/']:
            request('GET', path, json_response=False)
    native = command('identity', 'python3', '-c', "import json,os,subprocess; print(json.dumps({'uid':os.getuid(),'machine':os.uname().machine,'firefox':subprocess.check_output(['firefox','--version'],stderr=subprocess.STDOUT,universal_newlines=True),'python':subprocess.check_output(['python3','--version'],universal_newlines=True)}))")
    record['identity'] = json.loads(native.stdout)
    assert record['identity']['uid'] == 1200 and record['identity']['machine'] == 'x86_64'
    command('create-owned-directory', 'python3', '-c', 'import os,sys;os.mkdir(sys.argv[1],0o700)', root)
    handlers = {'defaultHandlersVersion': {'en-US': 4}, 'mimeTypes': {'application/sh': {'action': 2, 'ask': False, 'handlers': [{'name': 'Native shell canary', 'path': '/bin/sh'}], 'extensions': ['sh']}}, 'schemes': {}}
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, 'w', zipfile.ZIP_DEFLATED) as archive:
        archive.writestr('handlers.json', json.dumps(handlers))
    record['profile_sha256'] = hashlib.sha256(buffer.getvalue()).hexdigest()
    profile = base64.b64encode(buffer.getvalue()).decode()
    capabilities = {'browserName': 'firefox', 'moz:firefoxOptions': {'profile': profile, 'prefs': {'browser.download.folderList': 2, 'browser.download.dir': root}}}
    create_status, envelope = request('POST', api + '/session', {'capabilities': {'alwaysMatch': capabilities}})
    assert create_status == 200, envelope
    created = envelope.get('value', {})
    active = envelope.get('sessionId') or created.get('sessionId')
    assert active, ('Native session ID absent', envelope)
    created = {'sessionId': active, 'capabilities': created.get('capabilities', created)}
    record['create_envelope'] = envelope
    record['session'] = {'id': active, 'capabilities': created['capabilities']}
    save()
    assert created['capabilities']['browserName'] == 'firefox'
    browser_version = created['capabilities'].get('browserVersion') or created['capabilities'].get('version')
    assert browser_version and browser_version in record['identity']['firefox']
    ok('POST', api + '/session/' + active + '/url', {'url': 'data:text/html,<title>Native Selenium control</title><p>module-target-browser</p>'})
    assert ok('GET', api + '/session/' + active + '/title') == 'Native Selenium control'
    assert ok('POST', api + '/session/' + active + '/execute/sync', {'script': 'return document.body.textContent;', 'args': []}) == 'module-target-browser'
    record['ordinary_browser_passed'] = True
    save()
    profile_path = created['capabilities']['moz:profile']
    observed = command('effective-browser-profile', 'python3', '-c', (Path(__file__).parent / 'inspect_profile.py').read_text(), profile_path)
    record['effective_profile'] = json.loads(observed.stdout)
    ok('POST', api + '/session/' + active + '/timeouts', {'pageLoad': 5000})
    save()
    script = "printf 'native-handler\\n' > " + marker + '\n'
    raw = script.encode()
    record['canary'] = {'marker': marker, 'expected_base64': base64.b64encode(expected).decode(), 'script_base64': base64.b64encode(raw).decode()}
    save()
    try:
        status, navigation = request('POST', api + '/session/' + active + '/url', {'url': 'data:application/sh;charset=utf-8;base64,' + base64.b64encode(raw).decode()})
        record['handler_navigation'] = {'status': status, 'data': navigation}
    except TimeoutError as error:
        record['handler_navigation'] = {'error': type(error).__name__, 'message': str(error)}
    deadline = time.monotonic() + 20
    while True:
        probe = command('wait-native-handler', 'test', '-f', marker, required=False)
        if probe.returncode == 0:
            break
        assert time.monotonic() < deadline, 'Native external-handler marker absent'
        time.sleep(1)
    proof = command('verify-native-handler', 'python3', '-c', "from pathlib import Path;import base64,json,sys; p=Path(sys.argv[1]); print(json.dumps({'base64':base64.b64encode(p.read_bytes()).decode(),'uid':p.stat().st_uid}))", marker)
    record['handler_proof'] = json.loads(proof.stdout)
    assert record['handler_proof'] == {'base64': base64.b64encode(expected).decode(), 'uid': 1200}
    record['external_handler_passed'] = True
    save()
except BaseException as error:
    record['failure'] = {'type': type(error).__name__, 'message': str(error)}
    save()
finally:
    try:
        observed = command('owned-marker-observation', 'python3', '-c', "from pathlib import Path;import base64,json,sys; p=Path(sys.argv[1]); print(json.dumps({'exists':p.is_file(),'base64':base64.b64encode(p.read_bytes()).decode() if p.is_file() else None,'uid':p.stat().st_uid if p.exists() else None}))", marker)
        record['independent_marker_observation'] = json.loads(observed.stdout)
        save()
    except BaseException as error:
        record['marker_observation_error'] = {'type': type(error).__name__, 'message': str(error)}
    if active:
        try:
            record['browser_cleanup'] = {'id': active, 'response': ok('DELETE', api + '/session/' + active)}
            active = None
        except BaseException as error:
            record['browser_cleanup_error'] = {'type': type(error).__name__, 'message': str(error)}
    try:
        remaining, record['final_status'] = sessions()
        record['remaining_sessions'] = remaining
        assert not remaining
        cleanup = command('remove-owned-directory', 'python3', '-c', "from pathlib import Path;import base64,hashlib,json,shutil,sys; p=Path(sys.argv[1]); assert p.parent==Path('/tmp') and p.name.startswith('module-target-selenium-native-') and not p.is_symlink(); rows={str(x.relative_to(p)):{'sha256':hashlib.sha256(x.read_bytes()).hexdigest(),'base64':base64.b64encode(x.read_bytes()).decode(),'uid':x.stat().st_uid} for x in p.rglob('*') if x.is_file()}; assert all(x['uid']==1200 for x in rows.values()); shutil.rmtree(p);print(json.dumps({'files':rows,'absent':not p.exists()}))", root)
        record['artifact_cleanup'] = json.loads(cleanup.stdout)
        for name in ['memory.events', 'pids.events']:
            result = command('final-' + name, 'cat', '/sys/fs/cgroup/' + name)
            values = dict(line.split() for line in result.stdout.decode().splitlines())
            assert (values['oom'] == values['oom_kill'] == '0') if name == 'memory.events' else values['max'] == '0'
    except BaseException as error:
        record['recovery_error'] = {'type': type(error).__name__, 'message': str(error)}
    record['passed'] = bool(record.get('ordinary_browser_passed') and record.get('external_handler_passed') and not record.get('failure') and not record.get('browser_cleanup_error') and not record.get('recovery_error'))
    save()
    print(json.dumps({key: record.get(key) for key in ['passed', 'ordinary_browser_passed', 'external_handler_passed', 'failure', 'browser_cleanup_error', 'recovery_error']}))
raise SystemExit(0 if record['passed'] else 1)
