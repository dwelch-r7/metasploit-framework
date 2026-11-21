"""Prove Salt's actual command-injection and authentication fix boundaries."""

from pathlib import Path
import base64
import json
import os
import ssl
import subprocess
import sys
import urllib.error
import urllib.request

version = sys.argv[1]
assert version in ['3000.4', '3000.5']
runtime = json.loads(Path(os.environ['MODULE_TARGET_RUNTIME']).read_text())
directory = Path(runtime['artifacts'])
state = dict(version=version, commands=[], http=[], module_invoked=False)
endpoint = runtime['endpoints']['target']
base = 'https://' + endpoint['host'] + ':' + str(endpoint['port'])


def save():
    (directory/'salt-api-fixed-native.json').write_text(json.dumps(state, indent=2)+'\n')


def command(label, *arguments):
    argv = runtime['compose'] + ['exec', '-T', 'target', *arguments]
    process = subprocess.run(argv, capture_output=True, timeout=45)
    state['commands'].append(dict(label=label, argv=argv, exit=process.returncode, stdout_base64=base64.b64encode(process.stdout).decode(), stderr=process.stderr.decode(errors='replace')))
    save()
    assert process.returncode == 0, state['commands'][-1]
    return process.stdout


def observe(action, *arguments):
    return json.loads(command(action, 'python', '/opt/module-target/observe.py', action, *arguments))


def request(path, payload=None):
    data = None if payload is None else json.dumps(payload).encode()
    req = urllib.request.Request(base+path, data=data, headers={'Content-Type':'application/json', 'Accept':'application/json'})
    try:
        response = urllib.request.urlopen(req, context=ssl._create_unverified_context(), timeout=30)
    except urllib.error.HTTPError as error:
        response = error
    with response:
        row = dict(status=response.status, headers=dict(response.headers), body_base64=base64.b64encode(response.read()).decode())
    state['http'].append(dict(path=path, payload=payload, response=row))
    save()
    return row


def empty_result(response):
    return response['status'] == 200 and json.loads(base64.b64decode(response['body_base64'])) == {'return':[{}]}


try:
    metadata = observe('metadata')
    vendor = json.loads(Path('test/module_targets/salt_api/vendor.json').read_text())['profiles'][version] if version == '3000.4' else json.loads(Path('test/module_targets/salt_api_fixed/vendor-3000.5.json').read_text())
    assert metadata['uid'] == 0 and metadata['salt'] == version and metadata['cherrypy'] == '18.6.0', metadata
    assert metadata['files_sha256'] == vendor['files_sha256']
    state['metadata'] = metadata
    assert observe('artifacts') == dict(exists=False)
    state['before'] = observe('snapshot')
    stores = json.loads(command('shared-auth-stores', 'python', '-c', 'import json,salt.config;from pathlib import Path;r=json.loads(Path("/var/run/salt/module-target-api.json").read_text());print(json.dumps({name:{key:opts[key] for key in ["cachedir","pki_dir","token_dir"]} for name,role in r["roles"].items() for opts in [salt.config.master_config(role["config"]) ]}))'))
    assert stores['master'] == stores['api'], stores
    state['auth_stores'] = stores
    assert request('/')['status'] == 200
    credentials = dict(eauth='sharedsecret', username='nativefixture', password='module-target-salt-api-password')
    valid = request('/login', credentials)
    assert valid['status'] == 200
    session_id = json.loads(base64.b64decode(valid['body_base64']))['return'][0]['token']
    assert session_id and session_id != '0'*40
    assert request('/login', dict(credentials, password='wrong-password'))['status'] == 401
    # /login returns a CherryPy session identifier. /run's token field expects
    # a Salt eauth token, which the separate /token endpoint issues.
    issued = request('/token', credentials)
    assert issued['status'] == 200, issued
    token_data = json.loads(base64.b64decode(issued['body_base64']))
    assert isinstance(token_data, list) and len(token_data) == 1, token_data
    assert token_data[0]['name'] == 'nativefixture' and token_data[0]['eauth'] == 'sharedsecret', token_data
    token = token_data[0]['token']
    assert token and token not in [session_id, '0'*40]
    key = '/tmp/module-target-saltapi-fixed-native-key'
    command('ordinary-keygen', 'python', '-c', 'import salt.client.ssh.shell,sys;salt.client.ssh.shell.gen_key(sys.argv[1])', key)
    command('ordinary-public-key', 'ssh-keygen', '-l', '-f', key+'.pub')
    low = dict(client='ssh', tgt='*', fun='test.ping', ssh_priv=key)
    assert empty_result(request('/run', dict(low, **credentials)))
    assert empty_result(request('/run', dict(low, token=token)))
    session_reply = request('/run', dict(low, token=session_id))
    assert empty_result(session_reply) if version == '3000.4' else session_reply['status'] == 401, session_reply
    state['web_session_as_salt_token'] = session_reply
    assert request('/run', low)['status'] == 401
    state['invalid_auth'] = []
    # CherryPy rejects non-hex tokens before NetapiClient sees them. Use an
    # unknown, correctly formatted token to test authentication independently.
    assert request('/run', dict(low, token='native_invalid_token'))['status'] == 401
    for auth in [dict(eauth='native_invalid_auth'), dict(token='0'*40)]:
        reply = request('/run', dict(low, **auth))
        assert empty_result(reply) if version == '3000.4' else reply['status'] == 401, reply
        state['invalid_auth'].append(reply)

    marker = b'salt-api-fixed-native'
    path = '/tmp/module-target-saltapi-fixed-proof'
    shell = 'printf %s salt-api-fixed-native > '+path
    assert observe('proof', path) == dict(exists=False)
    command('ordinary-exact-command', 'sh', '-c', shell)
    assert observe('proof', path) == dict(exists=True, uid=0, base64=base64.b64encode(marker).decode())
    assert observe('proof', path, 'remove') == dict(exists=False)
    injected = '/dev/null < /dev/null & ('+shell+') & #'
    command('literal-keygen', 'python', '-c', 'import salt.client.ssh.shell,sys;salt.client.ssh.shell.gen_key(sys.argv[1])', injected)
    command('literal-public-key', 'ssh-keygen', '-l', '-f', injected+'.pub')
    assert observe('proof', path) == dict(exists=False)
    command('remove-literal-cli-key', 'rm', '-f', '--', injected, injected+'.pub')
    command('literal-key-absent-before-api', 'python', '-c', 'from pathlib import Path;import sys;assert not Path(sys.argv[1]).exists();assert not Path(sys.argv[1]+".pub").exists()', injected)
    reply = request('/run', dict(low, ssh_priv=injected, eauth='native_invalid_auth'))
    assert empty_result(reply) if version == '3000.4' else reply['status'] == 401, reply
    assert observe('proof', path) == dict(exists=False)
    if version == '3000.4':
        command('independent-api-literal-public-key', 'ssh-keygen', '-l', '-f', injected+'.pub')
    else:
        command('auth-denial-created-no-key', 'python', '-c', 'from pathlib import Path;import sys;assert not Path(sys.argv[1]).exists();assert not Path(sys.argv[1]+".pub").exists()', injected)
    state['command'] = dict(command=shell, path=path, marker_base64=base64.b64encode(marker).decode(), cli_blocked=True, api_blocked=True)
    state['keygen_artifacts'] = observe('artifacts')
    command('remove-ordinary-key', 'rm', '-f', '--', key, key+'.pub')
    assert observe('snapshot') == state['before']
    state['passed'] = True
finally:
    state['after'] = observe('snapshot')
    state['fixture_artifacts_removed'] = observe('artifacts', 'remove')
    save()
print(json.dumps(dict(passed=state.get('passed'), version=version, module_invoked=False)))
