"""Native LiteLLM HTTP, schema, role and state controls on the isolated lab."""
import base64
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import uuid


ROOT = Path(__file__).resolve().parent
RUNTIME = json.loads(Path(os.environ['MODULE_TARGET_RUNTIME']).read_text())
ARTIFACTS = Path(RUNTIME['artifacts'])
VERSION = os.environ['LITELLM_TARGET_VERSION']
CONFIGURATION = os.environ['LITELLM_TARGET_CONFIGURATION']
VENDOR = json.loads((ROOT / 'vendor.json').read_text())[VERSION]
ENV = dict(os.environ, DOCKER_CONTEXT='default', BUILDX_BUILDER='default')
MASTER = 'sk-module-target-master-key'
AUDIT_TABLES = {'LiteLLM_SpendLogs', 'LiteLLM_DailyTeamSpend', 'LiteLLM_DailyUserSpend'}
REQUEST_PROGRAM = r'''import base64,hashlib,json,sys,time,urllib.request,urllib.error
args=json.loads(sys.argv[1]);headers={'Content-Type':'application/json'}
if args.get('token') is not None:headers['Authorization']='Bearer '+args['token']
data=json.dumps(args['body'],ensure_ascii=False).encode('utf-8') if args.get('body') is not None else None
req=urllib.request.Request('http://127.0.0.1:'+str(args.get('port',4000))+args['path'],data=data,headers=headers);start=time.monotonic()
try:
 try:response=urllib.request.urlopen(req,timeout=8)
 except urllib.error.HTTPError as error:response=error
 raw=response.read();result=dict(status=response.status,seconds=time.monotonic()-start,headers=dict(response.headers),body_base64=base64.b64encode(raw).decode())
except (urllib.error.URLError,TimeoutError,ConnectionError) as error:result=dict(transport_error=type(error).__name__,message=str(error),seconds=time.monotonic()-start)
print(json.dumps(result))'''


def record(name, value):
    with (ARTIFACTS / name).open('a') as stream:
        stream.write(json.dumps(value, ensure_ascii=True) + '\n')


def command(argv, input_text=None, require=True):
    result = subprocess.run(argv, env=ENV, input=input_text, capture_output=True, text=True, timeout=30)
    record('litellm-native-commands.jsonl', dict(argv=argv, actual_exit=result.returncode, stdout=result.stdout, stderr=result.stderr))
    if require:
        assert result.returncode == 0, (argv, result.returncode, result.stderr)
    return result


def compose(*arguments, **kwargs):
    return command(RUNTIME['compose'] + list(arguments), **kwargs)


def target_python(program, arguments=None):
    return json.loads(compose('exec', '-T', 'target', 'python', '-B', '-c', program, json.dumps(arguments)).stdout)


def http(name, path, token=None, body=None, port=4000):
    result = target_python(REQUEST_PROGRAM, dict(path=path, token=token, body=body, port=port))
    result.update(name=name, path=path)
    record('litellm-native-http.jsonl', result)
    return result


def sql(statement, role='module_framework', database='module_litellm', require=True):
    password = 'module-target-framework-db-password' if role == 'module_framework' else 'module-target-litellm-db-password'
    return compose('exec', '-T', '-e', 'PGPASSWORD=' + password, 'reporting_db', 'psql', '-X', '-v', 'ON_ERROR_STOP=1',
                   '-h', '127.0.0.1', '-U', role, '-d', database, '-At', input_text=statement, require=require)


def state():
    # psql executes one generated SELECT per table without creating a function
    # or changing the vendor schema. Retain audit rows separately, never erase them.
    query = r"""SELECT format('SELECT json_build_object(%L,coalesce(jsonb_agg(to_jsonb(t) ORDER BY to_jsonb(t)::text),''[]''::jsonb)) FROM %I t;',tablename,tablename)
FROM pg_tables WHERE schemaname='public' ORDER BY tablename
\gexec
"""
    rows = {}
    for line in sql(query).stdout.splitlines():
        rows.update(json.loads(line))
    business = {table: values for table, values in rows.items() if table not in AUDIT_TABLES}
    captured = dict(business=business, audit={table: rows[table] for table in sorted(AUDIT_TABLES)})
    record('litellm-native-states.jsonl', captured)
    return dict(business_sha256=hashlib.sha256(json.dumps(business, sort_keys=True, ensure_ascii=True).encode()).hexdigest(),
                virtual_keys=len(rows['LiteLLM_VerificationToken']), audit_counts={table: len(rows[table]) for table in sorted(AUDIT_TABLES)})


def inspect_services():
    config = json.loads(compose('config', '--format', 'json').stdout)
    assert set(config['services']) == {'target', 'reporting_db', 'framework'}
    assert config['networks']['default']['internal'] is True
    network_name = config['networks']['default']['name']
    project = RUNTIME['compose'][RUNTIME['compose'].index('--project-name') + 1]
    expected = {'target': (2048, 1, 192), 'reporting_db': (512, 0.5, 96), 'framework': (1024, 1, 256)}
    result = {}
    for service, (memory, cpus, pids) in expected.items():
        identifier = compose('ps', '-q', service).stdout.strip()
        entry = json.loads(command(['docker', 'inspect', identifier]).stdout)[0]
        assert entry['Config']['Labels']['com.docker.compose.project'] == project
        assert entry['Config']['Labels']['com.docker.compose.service'] == service
        assert entry['State']['Running'] and not entry['State']['OOMKilled']
        assert entry['State']['Health']['Status'] == 'healthy'
        assert list(entry['NetworkSettings']['Networks']) == [network_name]
        assert not entry['HostConfig']['PortBindings'] and not entry['HostConfig']['Privileged']
        host = entry['HostConfig']
        assert host['Memory'] == host['MemorySwap'] == memory * 1024**2
        assert host['NanoCpus'] == int(cpus * 1e9) and host['PidsLimit'] == pids
        if service == 'target':
            assert entry['Config']['Image'] == VENDOR['image']
        limits = compose('exec', '-T', service, 'sh', '-c',
                         'for name in memory.max cpu.max pids.max memory.events pids.events memory.peak; do echo "$name"; cat "/sys/fs/cgroup/$name"; done').stdout
        assert 'memory.max\n' + str(memory * 1024**2) + '\n' in limits
        assert 'cpu.max\n' + str(int(cpus * 100000)) + ' 100000\n' in limits
        assert 'pids.max\n' + str(pids) + '\n' in limits
        assert 'oom 0\n' in limits and 'oom_kill 0\n' in limits and 'pids.events\nmax 0\n' in limits
        result[service] = dict(id=identifier, image=entry['Config']['Image'], address=entry['NetworkSettings']['Networks'][network_name]['IPAddress'], cgroup=limits)
    (ARTIFACTS / ('litellm-services-' + sys.argv[1] + '.json')).write_text(json.dumps(result, indent=2) + '\n')
    return result


def seed(count):
    path = ARTIFACTS / 'litellm-native-keys.json'
    keys = json.loads(path.read_text()) if path.exists() else []
    current = int(sql('SELECT count(*) FROM "LiteLLM_VerificationToken"').stdout)
    assert current == len(keys) and current <= count
    while len(keys) < count:
        result = http('generate-key', '/key/generate', MASTER, {})
        assert result['status'] == 200, result
        value = json.loads(base64.b64decode(result['body_base64']))
        assert value['key'].startswith('sk-')
        digest = hashlib.sha256(value['key'].encode()).hexdigest()
        assert sql('SELECT count(*) FROM "LiteLLM_VerificationToken" WHERE token=\'' + digest + "'").stdout.strip() == '1'
        keys.append(value['key'])
        path.write_text(json.dumps(keys) + '\n')
    assert http('virtual-key-model-list', '/v1/models', keys[0])['status'] == 200
    assert http('master-key-info', '/key/info?key=' + keys[0], MASTER)['status'] == 200
    return state()


def calibrate():
    count = int(sql('SELECT count(*) FROM "LiteLLM_VerificationToken"').stdout)
    body = dict(model='gpt-3.5-turbo', messages=[dict(role='user', content='x')], max_tokens=1)
    expected_slow = count > 0 and VERSION == '1.83.3' and CONFIGURATION == 'affected'
    observations = []
    for name, condition, prefix, model in [('true', '1=1', '', 'gpt-3.5-turbo'), ('false', '1=2', '', 'gpt-3.5-turbo'),
                                           ('sk-prefix', '1=1', 'sk-', 'gpt-3.5-turbo'), ('unicode-true', '1=1', '', 'module-native-caf\u00e9-\u96ea'),
                                           ('unicode-false', '1=2', '', 'module-native-caf\u00e9-\u96ea')]:
        token = prefix + "' OR 1=(case when " + condition + ' then (select 1 from pg_sleep(1)) else 1 end)-- ' + uuid.uuid4().hex[:8]
        result = http('calibrate-' + name, '/v1/chat/completions', token, dict(body, model=model))
        assert result.get('status') == 401, result
        delayed = expected_slow and name in ('true', 'unicode-true')
        assert (.9 <= result['seconds'] < 3) if delayed else result['seconds'] < .5, result
        observations.append(result)
    return dict(virtual_keys=count, delayed=expected_slow, observations=observations)


action = sys.argv[1]
if action == 'before':
    identities = inspect_services()
    installed = target_python("import hashlib,importlib.metadata,json,pathlib;root=pathlib.Path('/app/litellm');print(json.dumps(dict(packages={name:importlib.metadata.version(name) for name in json.loads(__import__('sys').argv[1])},utils_sha256=hashlib.sha256((root/'proxy/utils.py').read_bytes()).hexdigest())))", list(VENDOR['packages']))
    assert installed == dict(packages=VENDOR['packages'], utils_sha256=VENDOR['utils_sha256'])
    assert int(sql('SELECT count(*) FROM "_prisma_migrations" WHERE finished_at IS NOT NULL AND rolled_back_at IS NULL').stdout) > 0
    assert sql('SELECT current_user,rolsuper,rolcreatedb,rolcreaterole,rolreplication FROM pg_roles WHERE rolname=current_user', role='module_litellm').stdout.strip() == 'module_litellm|f|f|f|f'
    denied = sql('SELECT 1', role='module_litellm', database='module_targets', require=False)
    assert denied.returncode == 2 and 'permission denied for database' in denied.stderr
    assert int(sql('SELECT count(*) FROM "LiteLLM_VerificationToken"').stdout) == 0
    refused = http('refused-port', '/', port=1)
    assert refused.get('transport_error') == 'URLError' and 'refused' in refused['message'].lower()
    assert http('missing-route', '/module-native-absent')['status'] == 404
    output = dict(version=VERSION, configuration=CONFIGURATION, installed=installed, identities=identities, empty=calibrate(), state=state())
elif action == 'seed':
    output = seed(int(sys.argv[2]))
elif action == 'calibrate':
    output = calibrate()
elif action == 'state':
    output = state()
elif action == 'after':
    output = dict(identities=inspect_services(), state=state())
else:
    raise ValueError('Unknown native action: ' + action)
print(json.dumps(output, ensure_ascii=True))
