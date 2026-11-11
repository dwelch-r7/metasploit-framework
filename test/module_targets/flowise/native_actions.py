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
RESET_TRANSACTION_ERROR = 'Transaction is not started yet, start transaction before committing or rolling it back.'
SQLITE_READONLY_SCRIPT = '''import sqlite3,json,sys
c=sqlite3.connect('file:/root/.flowise/database.sqlite?mode=ro',uri=True)
c.execute('PRAGMA query_only=ON')
'''


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
    script = '''const fs=require('fs'),p=require('path'),crypto=require('crypto'),{createRequire}=require('module');
const root=p.dirname(p.dirname(fs.realpathSync('/usr/local/bin/flowise')));
const lookup=createRequire(p.join(root,'package.json')),packages=new Map();
// package.json can be private. Resolve the public entrypoint without loading
// it, then validate its manifest in the genuine dependency lookup order.
function installedPackage(name){
if(packages.has(name))return packages.get(name);
let manifest,entrypoint;
if(name==='flowise'){manifest=p.join(root,'package.json');entrypoint=fs.realpathSync('/usr/local/bin/flowise');}
else{
 entrypoint=fs.realpathSync(lookup.resolve(name));
 for(const directory of lookup.resolve.paths(name)||[]){
  const candidate=p.join(directory,name,'package.json');
  if(fs.existsSync(candidate)){manifest=fs.realpathSync(candidate);break;}
 }
 if(!manifest)throw new Error('Installed package manifest not found: '+name);
}
const metadata=JSON.parse(fs.readFileSync(manifest)),packageRoot=fs.realpathSync(p.dirname(manifest));
if(metadata.name!==name||typeof metadata.version!=='string')throw new Error('Unexpected installed package identity: '+manifest);
const relative=p.relative(packageRoot,entrypoint);
if(relative==='..'||relative.startsWith('..'+p.sep)||p.isAbsolute(relative))throw new Error('Resolved entrypoint is outside package: '+name);
const result={manifest,root:packageRoot,entrypoint,name:metadata.name,version:metadata.version};packages.set(name,result);return result;
}
const expected=JSON.parse(process.argv[1]);
const rows=expected.map(item=>{try{const resolved=installedPackage(item.package),location=p.join(resolved.root,item.path),bytes=fs.readFileSync(location);
return {...item,location,package_manifest:resolved.manifest,package_entrypoint:resolved.entrypoint,package_name:resolved.name,package_version:resolved.version,actual_base64:bytes.toString('base64'),actual_sha256:crypto.createHash('sha256').update(bytes).digest('hex')};}catch(error){return {...item,actual_error:{code:error.code,message:error.message}};}});
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


def sqlite_readonly(native, script, *arguments):
    return json.loads(native.cli('app', 'python3', '-c', SQLITE_READONLY_SCRIPT + script, *arguments)['stdout'])


def account_state(native, email_address):
    # Discover the actual account table/columns and read only the fixture row.
    # The connection mode and query_only reuse the existing persistence control.
    script = '''c.row_factory=sqlite3.Row
matches=[]
for (name,) in c.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name").fetchall():
 quote=lambda value:'"'+value.replace('"','""')+'"'
 columns={row[1].replace('_','').lower():row[1] for row in c.execute('PRAGMA table_info('+quote(name)+')')}
 if {'id','email','credential','temptoken','tokenexpiry'}.issubset(columns):
  for row in c.execute('SELECT * FROM '+quote(name)+' WHERE '+quote(columns['email'])+'=?',(sys.argv[1],)):
   matches.append({'table':name,'columns':columns,'row':dict(row)})
print(json.dumps({'query_only':c.execute('PRAGMA query_only').fetchone()[0],'matches':matches}))'''
    result = sqlite_readonly(native, script, email_address)
    assert result['query_only'] == 1 and len(result['matches']) == 1, 'Read-only account snapshot must identify exactly one fixture account'
    return result['matches'][0]


def known_reset_transaction_error(status, body):
    """Match the pinned target exception; this alone does not prove replay denial."""
    if type(status) is not int or status != 500:
        return False
    try:
        value = json.loads(body)
    except (json.JSONDecodeError, UnicodeDecodeError):
        return False
    expected = {'statusCode': 500, 'success': False, 'message': RESET_TRANSACTION_ERROR, 'stack': {}}
    return isinstance(value, dict) and value == expected and type(value['statusCode']) is int and value['success'] is False


def consumed_token_replay(native, email_address, token, current_password):
    assert native.definition['version'] in ['3.0.5', '3.0.6'], 'Consumed-token exception control requires the pinned SMTP profile'
    assert email_address == EMAIL and isinstance(token, str) and token, 'Consumed-token replay must identify the actual fixture account and token'
    before = account_state(native, email_address)
    assert before['row'][before['columns']['temptoken']] in ['', None], 'Successful reset did not consume the fixture token'
    replay_password = 'FlowiseReplay!42' if current_password != 'FlowiseReplay!42' else 'FlowiseAlternate!42'
    status, body = native.request('/api/v1/account/reset-password', {'user': {'email': email_address, 'tempToken': token, 'password': replay_password}})
    # Observe the replay's database effect before authentication probes can
    # legitimately affect login metadata or session tables.
    after = account_state(native, email_address)
    current_status = login(native, current_password)[0]
    replay_status = login(native, replay_password)[0]
    # The pinned handlers throw before startTransaction, then mask that error
    # with unconditional rollback. Only this captured 500 shape is supported,
    # together with independent real state and fresh credential controls.
    assert known_reset_transaction_error(status, body), 'Consumed-token replay did not return the exact captured target exception'
    assert before == after, 'Consumed-token replay changed the fixture account or token row'
    assert current_status in [200, 201], 'Current password no longer authenticates after consumed-token replay'
    assert replay_status == 401, 'Distinct consumed-token replay password was not refused'
    return {'replay_rejected': True, 'reused_token_status': status, 'response_base64': base64.b64encode(body).decode(),
            'distinct_replay_password': True, 'current_password_login_status': current_status, 'replay_password_login_status': replay_status,
            'account_state_unchanged': True, 'before': before, 'after': after}


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
    replay = consumed_token_replay(native, EMAIL, token, password)
    return {'forgot_status': 201, 'response_base64': base64.b64encode(body).decode(), 'email_delivered': True, 'reset_status': status, 'login_accepted': True,
            'reused_token_status': replay['reused_token_status'], 'consumed_token_proof': replay}


def persistence_control(native):
    client = authenticated(native)
    name = 'module-native-' + uuid.uuid4().hex
    status, body = native.request('/api/v1/chatflows', {'name': name, 'flowData': '{"nodes":[],"edges":[]}', 'deployed': False, 'isPublic': False, 'type': 'CHATFLOW'}, client=client, headers=headers(native))
    assert status == 200, (status, body)
    identifier = json.loads(body)['id']
    script = '''rows=[]
for (name,) in c.execute("SELECT name FROM sqlite_master WHERE type='table'"):
 q='"'+name.replace('"','""')+'"'
 columns=[r[1] for r in c.execute('PRAGMA table_info('+q+')')]
 if 'id' in columns:
  count=c.execute('SELECT count(*) FROM '+q+' WHERE id=?',(sys.argv[1],)).fetchone()[0]
  if count:rows.append({'table':name,'matching_id_count':count})
print(json.dumps(rows))'''
    persisted = sqlite_readonly(native, script, identifier)
    assert len(persisted) == 1 and persisted[0]['matching_id_count'] == 1
    deleted, response = native.request('/api/v1/chatflows/' + identifier, client=client, headers=headers(native), method='DELETE')
    assert deleted == 200, (deleted, response)
    assert sqlite_readonly(native, script, identifier) == []
    return {'chatflow_id': identifier, 'persisted_native_sqlite_rows': persisted, 'delete_status': deleted, 'native_sqlite_absence': True}
