"""Qualify real Salt API authentication, key generation and exact commands."""

from pathlib import Path
import base64
import json
import os
import ssl
import subprocess
import time
import urllib.error
import urllib.request

runtime = json.loads(Path(os.environ['MODULE_TARGET_RUNTIME']).read_text())
directory = Path(runtime['artifacts'])
state = dict(commands=[], http=[], module_invoked=False)
endpoint = runtime['endpoints']['target']
base = 'https://' + endpoint['host'] + ':' + str(endpoint['port'])
context = ssl._create_unverified_context()


def save():
    (directory/'salt-api-native.json').write_text(json.dumps(state, indent=2)+'\n')


def command(label, *argv):
    args = runtime['compose'] + ['exec', '-T', 'target', *argv]
    process = subprocess.run(args, capture_output=True, timeout=40)
    state['commands'].append(dict(label=label, argv=args, exit=process.returncode, stdout_base64=base64.b64encode(process.stdout).decode(), stderr=process.stderr.decode(errors='replace')))
    save()
    assert process.returncode == 0, state['commands'][-1]
    return process.stdout


def observe(action, *args):
    return json.loads(command(action, 'python', '/opt/module-target/observe.py', action, *args))


def request(method, path, payload=None):
    data = None if payload is None else json.dumps(payload).encode()
    req = urllib.request.Request(base+path, data=data, method=method, headers={'Content-Type':'application/json', 'Accept':'application/json'})
    try:
        response = urllib.request.urlopen(req, context=context, timeout=30)
    except urllib.error.HTTPError as error:
        response = error
    with response:
        body = response.read()
        row = dict(status=response.status, headers=dict(response.headers), body_base64=base64.b64encode(body).decode())
    state['http'].append(dict(method=method, path=path, payload=payload, response=row))
    save()
    return row


def await_proof(path, marker):
    deadline = time.monotonic()+8
    while True:
        actual = observe('proof', path)
        if actual.get('exists'):
            assert actual == dict(exists=True, uid=0, base64=base64.b64encode(marker).decode()), actual
            return actual
        assert time.monotonic() < deadline, actual
        time.sleep(0.1)


try:
    metadata = observe('metadata')
    vendor = json.loads(Path('test/module_targets/salt_api/vendor.json').read_text())
    assert metadata['uid'] == 0 and metadata['salt'] == '3000.1' and metadata['cherrypy'] == '18.6.0', metadata
    assert metadata['files_sha256'] == vendor['profiles']['3000.1']['files_sha256']
    state['metadata'] = metadata
    assert observe('artifacts') == dict(exists=False)
    state['before'] = observe('snapshot')
    root = request('GET', '/')
    assert root['status'] == 200
    valid = request('POST', '/login', dict(eauth='sharedsecret', username='nativefixture', password='module-target-salt-api-password'))
    assert valid['status'] == 200, valid
    data = json.loads(base64.b64decode(valid['body_base64']))
    assert data['return'][0]['user'] == 'nativefixture' and data['return'][0]['token']
    wrong = request('POST', '/login', dict(eauth='sharedsecret', username='nativefixture', password='wrong-password'))
    assert wrong['status'] == 401, wrong
    missing = request('POST', '/run', dict(client='ssh', tgt='*', fun='test.ping'))
    assert missing['status'] == 401, missing
    key = '/tmp/module-target-saltapi-native-key'
    command('native-keygen', 'python', '-c', 'import salt.client.ssh.shell,sys;salt.client.ssh.shell.gen_key(sys.argv[1])', key)
    command('native-key-fingerprint', 'ssh-keygen', '-l', '-f', key+'.pub')
    authorized = request('POST', '/run', dict(client='ssh', tgt='*', fun='test.ping', eauth='sharedsecret', username='nativefixture', password='module-target-salt-api-password', ssh_priv=key))
    assert authorized['status'] == 200 and json.loads(base64.b64decode(authorized['body_base64'])) == {'return':[{}]}, authorized
    command('remove-native-key', 'rm', '-f', '--', key, key+'.pub')
    state['controls'] = []
    cases = [
        ('plain', b'salt-api-native', 'printf %s salt-api-native'),
        ('rich', 'Salt "quoted" & 雪\r\n'.encode(), "printf '%s\\r\\n' 'Salt \"quoted\" & 雪'")
    ]
    for label, marker, producer in cases:
        path = '/tmp/module-target-saltapi-native-'+label
        assert observe('proof', path) == dict(exists=False)
        shell = producer+' > '+path
        injected = '/dev/null < /dev/null & ('+shell+') & #'
        command('native-cli-injection-'+label, 'python', '-c', 'import salt.client.ssh.shell,sys;salt.client.ssh.shell.gen_key(sys.argv[1])', injected)
        cli = await_proof(path, marker)
        assert observe('proof', path, 'remove') == dict(exists=False)
        reply = request('POST', '/run', dict(client='ssh', tgt='*', fun='test.ping', eauth='native_invalid_auth', ssh_priv=injected))
        assert reply['status'] == 200 and json.loads(base64.b64decode(reply['body_base64'])) == {'return':[{}]}, reply
        actual = await_proof(path, marker)
        assert observe('proof', path, 'remove') == dict(exists=False)
        state['controls'].append(dict(label=label, command=shell, path=path, marker_base64=base64.b64encode(marker).decode(), cli=cli, api=actual))
    state['keygen_artifacts'] = observe('artifacts')
    assert observe('snapshot') == state['before']
    state['passed'] = True
finally:
    state['after'] = observe('snapshot')
    state['fixture_artifacts_removed'] = observe('artifacts', 'remove')
    save()
print(json.dumps(dict(passed=state.get('passed'), version=state.get('metadata',{}).get('salt'), module_invoked=False)))
