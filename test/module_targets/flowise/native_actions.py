"""Ordinary native account, SMTP, MCP and harmless marker controls."""
import base64
import email
import io
import json
from pathlib import Path
import re
import tarfile
import uuid
import urllib.error

EMAIL = 'module_target@module-target.test'
PASSWORD = 'FlowiseNative!42'
BASIC = ('module_native', 'module-target-basic-password')
SMTP_PASSWORD = ' module-target: capture "quoted" \\ tail '


def login(native, password=PASSWORD):
    client = native.client()
    status, body = native.request('/api/v1/auth/login', {'email': EMAIL, 'password': password}, client=client, headers={'x-request-from': 'internal'})
    return status, body, client


def headers(native):
    result = {'x-request-from': 'internal'}
    if native.definition['mode'] == 'basic':
        result['Authorization'] = 'Basic ' + base64.b64encode(':'.join(BASIC).encode()).decode()
    return result


def authenticated(native):
    if native.definition['mode'] in ['open', 'basic']:
        return native.client()
    status, body, client = login(native)
    assert status in [200, 201], (status, body)
    return client


def mcp(native, config, client=None):
    return native.request('/api/v1/node-load-method/customMCP', {'loadMethod': 'listActions', 'inputs': {'mcpServerConfig': config}}, client=client, headers=headers(native))


def target_bytes(native, path):
    result = native.cli('app', 'node', '-e', 'const f=require("fs");if(f.existsSync(process.argv[1]))process.stdout.write(f.readFileSync(process.argv[1]).toString("base64"));else process.exit(3)', path, check=False)
    assert result['exitstatus'] in [0, 3]
    return None if result['exitstatus'] == 3 else base64.b64decode(result['stdout'])


def marker_observation(native, path, expected, seconds=5):
    # Native filesystem observation uses Node's bounded watcher, not HTTP status.
    script = '''const fs=require('fs'),p=process.argv[1],positive=process.argv[2]==='true';
let timer,complete=false;const finish=(ok,data)=>{if(complete)return;complete=true;fs.unwatchFile(p);clearTimeout(timer);if(data)process.stdout.write(data.toString('base64'));process.exitCode=ok?0:1;};
const observe=()=>{if(complete)return;if(fs.existsSync(p)){if(positive){const data=fs.readFileSync(p);if(data.toString()==='flowise-native-proof')finish(true,data);}else finish(false);}};
fs.watchFile(p,{interval:100},observe);timer=setTimeout(()=>{if(positive){const data=fs.existsSync(p)?fs.readFileSync(p):null;finish(!!data&&data.toString()==='flowise-native-proof',data&&data.toString()==='flowise-native-proof'?data:null);}else finish(!fs.existsSync(p));},Number(process.argv[3])*1000);observe();'''
    result = native.cli('app', 'node', '-e', script, path, str(expected).lower(), str(seconds))
    return base64.b64decode(result['stdout']) if expected else None


def remove(native, *paths):
    native.cli('app', 'rm', '-f', '--', *paths)
    for path in paths:
        assert target_bytes(native, path) is None


def identity(native):
    expected = json.loads((Path(__file__).parent / 'published_artifacts.json').read_text())[native.definition['version']]
    script = '''const fs=require('fs'),p=require('path'),crypto=require('crypto');
const root=p.dirname(p.dirname(fs.realpathSync('/usr/local/bin/flowise')));
const expected=JSON.parse(process.argv[1]);
const rows=expected.map(item=>{try{const packagePath=item.package==='flowise'?p.join(root,'package.json'):require.resolve(item.package+'/package.json',{paths:[root]});
const location=p.join(p.dirname(packagePath),item.path);const bytes=fs.readFileSync(location);
return {...item,location,actual_base64:bytes.toString('base64'),actual_sha256:crypto.createHash('sha256').update(bytes).digest('hex')};}catch(error){return {...item,actual_error:{code:error.code,message:error.message}};}});
let mail;
if(JSON.parse(process.argv[2])){
const mailer=p.join(root,'dist/enterprise/utils/sendEmail.js');
const nodemailerPath=require.resolve('nodemailer/package.json',{paths:[p.dirname(mailer)]});
const nodemailerBytes=fs.readFileSync(nodemailerPath);
const keys=['SMTP_HOST','SMTP_PORT','SMTP_SECURE','ALLOW_UNAUTHORIZED_CERTS','NODE_TLS_REJECT_UNAUTHORIZED'];
mail={environment:Object.fromEntries(keys.map(key=>[key,process.env[key]??null])),nodemailer:{path:nodemailerPath,version:JSON.parse(nodemailerBytes).version,sha256:crypto.createHash('sha256').update(nodemailerBytes).digest('hex')}};
}
const v8=require('v8');console.log(JSON.stringify({node:process.version,root,rows,mail,heap_limit:v8.getHeapStatistics().heap_size_limit,execArgv:process.execArgv}));'''
    result = json.loads(native.cli('app', 'node', '-e', script, json.dumps(expected), json.dumps(native.definition['smtp']))['stdout'])
    for row in result['rows']:
        if 'actual_base64' in row:
            destination = native.artifacts / 'native-installed-source' / row['package'] / row['path']
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(base64.b64decode(row['actual_base64']))
    assert result['heap_limit'] <= 600 * 1024 * 1024
    assert all(row.get('actual_sha256') == row['sha256'] for row in result['rows']), result
    assert all(json.loads(base64.b64decode(row['actual_base64']))['version'] == native.definition['version'] for row in result['rows'] if row['path'] == 'package.json')
    if native.definition['smtp']:
        configured = native.config['services']['app']['environment']
        observed = result['mail']['environment']
        assert configured['ALLOW_UNAUTHORIZED_CERTS'] == observed['ALLOW_UNAUTHORIZED_CERTS'] == 'true'
        assert configured.get('NODE_TLS_REJECT_UNAUTHORIZED') is None and observed['NODE_TLS_REJECT_UNAUTHORIZED'] is None
        assert {key: observed[key] for key in ['SMTP_HOST', 'SMTP_PORT', 'SMTP_SECURE']} == {'SMTP_HOST': 'smtp', 'SMTP_PORT': '25', 'SMTP_SECURE': 'false'}
        result['mail']['verification_scope'] = 'unverified-local-TLS'
        # Pinned compiled mailer uses string truthiness; even 'false' opts out.
        result['mail']['option_semantics'] = 'Any nonempty ALLOW_UNAUTHORIZED_CERTS disables SMTP peer verification; fixture requires literal true'
    status, body = native.request('/api/v1/version')
    assert status == 200 and json.loads(body)['version'] == native.definition['version']
    native.cli('app', 'node', '--version')
    native.cli('app', 'npm', '--version')
    native.cli('app', 'npx', '--version')
    return result


def sdk_control(native):
    # Installed genuine MCP SDK handles the protocol; no hand-crafted responses.
    status, body = mcp(native, json.dumps({'command': 'node', 'args': ['native_mcp_tool.js']}), authenticated(native))
    assert status == 200, (status, body)
    data = json.loads(body)
    identifiers = [item['name'].removeprefix('module_native_pid_') for item in data if item.get('name', '').startswith('module_native_pid_')]
    assert len(identifiers) == 1 and identifiers[0].isdigit(), data
    pid = identifiers[0]
    tool = next(item for item in data if item.get('name') == 'module_native_pid_' + pid)
    live = json.loads(tool['description'])
    assert str(live['pid']) == pid
    process_status = live['self_status']
    uid = re.search(r'^Uid:\s+(\d+)', process_status, re.MULTILINE).group(1)
    assert uid == live['uid']
    # Tagged MCPToolkit.initialize awaits client.close before the HTTP result.
    # The SDK response retains the helper's real live /proc snapshot; require
    # natural vendor-driven process absence, never a guessed lingering PID.
    script = '''const fs=require('fs'),p=process.argv[1];let t;
const finish=()=>{if(!fs.existsSync(p)){clearTimeout(t);fs.unwatchFile(p);process.stdout.write('ABSENT');}};
fs.watchFile(p,{interval:100},finish);t=setTimeout(()=>{fs.unwatchFile(p);process.exitCode=fs.existsSync(p)?1:0;},10000);finish();'''
    assert native.cli('app', 'node', '-e', script, '/proc/' + pid)['stdout'] == 'ABSENT'
    return {'status': status, 'tools': data, 'pid': pid, 'uid': uid, 'process_status': process_status, 'vendor_initial_client_closed': True}


def command_control(native, primitive, expected):
    marker = '/tmp/module-target-flowise-native-' + uuid.uuid4().hex
    count = marker + '-count'
    command = 'printf %s flowise-native-proof>' + marker + ';printf x>>' + count
    native.cli('app', 'sh', '-c', command)
    assert target_bytes(native, marker) == b'flowise-native-proof' and target_bytes(native, count) == b'x'
    remove(native, marker, count)
    config = {'command': 'sh', 'args': ['-c', command]}
    if primitive == 'js':
        encoded = base64.b64encode(command.encode()).decode()
        config = '{x:(function(){process.mainModule.require("child_process").execSync(Buffer.from("' + encoded + '","base64").toString());return 1;})()}'
    elif primitive == 'npx':
        package_name = 'native' + uuid.uuid4().hex
        contents = {'package/package.json': json.dumps({'name': 'module-native', 'version': '1.0.0', 'bin': {'module-native': './index.js'}}).encode(), 'package/index.js': ('#!/usr/bin/env node\nrequire("child_process").execSync(Buffer.from("' + base64.b64encode(command.encode()).decode() + '","base64").toString());\n').encode()}
        with tarfile.open(native.artifacts / package_name, 'w') as archive:
            for name, data in contents.items():
                item = tarfile.TarInfo(name); item.size = len(data); item.mode = 0o755 if name.endswith('.js') else 0o644; archive.addfile(item, io.BytesIO(data))
        url = 'http://' + native.endpoints['gateway']['host'] + '/native/' + package_name
        config = json.dumps({'command': 'npx', 'args': ['--yes', url]})
    elif not isinstance(config, str):
        config = json.dumps(config)
    try:
        status, body = mcp(native, config, authenticated(native))
    except TimeoutError:
        status, body = None, b''
    except urllib.error.URLError as error:
        if not isinstance(error.reason, TimeoutError):
            raise
        status, body = None, b''
    if not expected:
        assert status is not None, 'A timeout is not a fixed-target refusal'
    observed = marker_observation(native, marker, expected, 10 if expected else 5)
    if expected:
        assert observed == b'flowise-native-proof'
        assert re.fullmatch(b'x+', target_bytes(native, count))
    else:
        assert target_bytes(native, count) is None
    result = {'primitive': primitive, 'expected_execution': expected, 'status': status, 'response_base64': base64.b64encode(body).decode(), 'marker': marker, 'observed_bytes_base64': base64.b64encode(observed).decode() if observed is not None else None, 'append_count': len(target_bytes(native, count) or b''), 'absence_window_seconds': 0 if expected else 5}
    remove(native, marker, count)
    return result


def spool(native):
    row = native.cli('smtp', 'cat', '/var/spool/exim4/module-target-mail/capture-message', check=False)
    return row['stdout'] if row['exitstatus'] == 0 else ''


def delivered_spool(native, previous, needle):
    # Exim acceptance precedes local delivery. Observe actual appended MIME with
    # a bounded target-side readiness predicate, not an unconditional delay.
    script = """import base64,pathlib,sys,time
p=pathlib.Path('/var/spool/exim4/module-target-mail/capture-message')
previous=base64.b64decode(sys.argv[1]);needle=sys.argv[2].encode();deadline=time.monotonic()+10;pause=0.05
while True:
 data=p.read_bytes() if p.exists() else b''
 if data.startswith(previous) and needle in data[len(previous):]:
  print(base64.b64encode(data).decode());break
 remaining=deadline-time.monotonic()
 if remaining<=0:raise TimeoutError('Actual Exim MIME delivery not observed within10seconds')
 time.sleep(min(pause,remaining));pause=min(pause*2,0.5)
"""
    encoded = base64.b64encode(previous.encode()).decode()
    return base64.b64decode(native.cli('smtp', 'python3', '-c', script, encoded, needle)['stdout']).decode()


def smtp_control(native):
    version = native.cli('smtp', 'exim4', '-bV')['stdout']
    assert 'Exim version 4.' in version
    previous = spool(native)
    script = '''import smtplib
from email.message import EmailMessage
s=smtplib.SMTP('127.0.0.1',25,timeout=10)
s.login('capture_user', %r)
m=EmailMessage();m['From']='module_target@module-target.test';m['To']='module_target@module-target.test';m['Subject']='Flowise native SMTP';m.set_content('Exact Flowise native SMTP proof')
s.send_message(m);s.quit()
''' % SMTP_PASSWORD
    native.cli('smtp', 'python3', '-c', script)
    message = delivered_spool(native, previous, 'Exact Flowise native SMTP proof')
    assert 'Exact Flowise native SMTP proof' in message
    return {'version': version, 'real_smtp_authentication': True, 'exact_native_message_present': True}


def restore_password(native, password=PASSWORD):
    previous = spool(native)
    status, body = native.request('/api/v1/account/forgot-password', {'user': {'email': EMAIL}})
    assert status == 201, (status, body)
    message = delivered_spool(native, previous, 'Subject: Reset your password')
    assert message.startswith(previous) and len(message) > len(previous)
    fresh = message[len(previous):]
    parsed = email.message_from_string(fresh)
    pieces = []
    for part in parsed.walk():
        if part.get_content_type() in ['text/plain', 'text/html']:
            pieces.append((part.get_payload(decode=True) or b'').decode(errors='replace'))
    tokens = re.findall(r'reset-password\?token=([^\s"<>]+)', '\n'.join(pieces))
    assert tokens, fresh
    token = tokens[-1]
    status, response = native.request('/api/v1/account/reset-password', {'user': {'email': EMAIL, 'tempToken': token, 'password': password}})
    assert status == 201, (status, response)
    assert login(native, password)[0] in [200, 201]
    reused, _ = native.request('/api/v1/account/reset-password', {'user': {'email': EMAIL, 'tempToken': token, 'password': password}})
    assert reused == 400
    return {'forgot_status': 201, 'response_base64': base64.b64encode(body).decode(), 'email_delivered': True, 'reset_status': status, 'login_accepted': True, 'reused_token_status': reused}


def persistence_control(native):
    client = authenticated(native)
    name = 'module-native-' + uuid.uuid4().hex
    status, body = native.request('/api/v1/chatflows', {'name': name, 'flowData': '{"nodes":[],"edges":[]}', 'deployed': False, 'isPublic': False, 'type': 'CHATFLOW'}, client=client, headers=headers(native))
    assert status == 200, (status, body)
    identifier = json.loads(body)['id']
    script = '''import sqlite3,json,sys
c=sqlite3.connect('file:/root/.flowise/database.sqlite?mode=ro',uri=True)
c.execute('PRAGMA query_only=ON')
rows=[]
for (name,) in c.execute("SELECT name FROM sqlite_master WHERE type='table'"):
 q='"'+name.replace('"','""')+'"'
 columns=[r[1] for r in c.execute('PRAGMA table_info('+q+')')]
 if 'id' in columns:
  count=c.execute('SELECT count(*) FROM '+q+' WHERE id=?',(sys.argv[1],)).fetchone()[0]
  if count:rows.append({'table':name,'matching_id_count':count})
print(json.dumps(rows))'''
    persisted = json.loads(native.cli('app', 'python3', '-c', script, identifier)['stdout'])
    assert len(persisted) == 1 and persisted[0]['matching_id_count'] == 1
    deleted, response = native.request('/api/v1/chatflows/' + identifier, client=client, headers=headers(native), method='DELETE')
    assert deleted == 200, (deleted, response)
    assert json.loads(native.cli('app', 'python3', '-c', script, identifier)['stdout']) == []
    return {'chatflow_id': identifier, 'persisted_native_sqlite_rows': persisted, 'delete_status': deleted, 'native_sqlite_absence': True}
