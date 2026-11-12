"""Genuine Audiobookshelf auth, SQLite, source and process controls."""
import base64
import hashlib
import http.client
import json
from pathlib import Path
import subprocess
import sys

runtime = json.loads(Path(sys.argv[1]).read_text())
profile, phase = sys.argv[2:4]
version = '2.19.1' if profile == 'fixed' else '2.19.0'
initialized = profile != 'uninitialized'
prefix = '/audiobookshelf'
requests, commands = [], []
result = {'status': 'starting', 'profile': profile, 'phase': phase,
          'requests': requests, 'commands': commands}
profiles = json.loads((Path(__file__).parent / 'profiles.json').read_text())


def execute(service, *argv, expected=0):
    process = subprocess.run(runtime['compose'] + ['exec', '-T', service, *argv], capture_output=True, timeout=60)
    row = {'service': service, 'argv': argv, 'exit': process.returncode,
           'stdout_base64': base64.b64encode(process.stdout).decode(),
           'stderr_base64': base64.b64encode(process.stderr).decode()}
    commands.append(row)
    assert process.returncode == expected, row
    return process.stdout


def request(path, method='GET', data=None, token=None):
    endpoint = runtime['endpoints']['target']
    connection = http.client.HTTPConnection(endpoint['host'], endpoint['port'], timeout=20)
    headers = {'Content-Type': 'application/json'}
    if token:
        headers['Authorization'] = 'Bearer ' + token
    try:
        connection.request(method, path, body=json.dumps(data).encode() if data is not None else None, headers=headers)
        response = connection.getresponse()
        body = response.read()
        requests.append({'method': method, 'path': path, 'authenticated': bool(token), 'status': response.status,
                         'body_base64': base64.b64encode(body).decode()})
        try:
            parsed = json.loads(body)
        except ValueError:
            parsed = None
        return response.status, body, parsed
    finally:
        connection.close()


def target_state():
    script = r'''
    const fs=require('fs'),crypto=require('crypto');const files={};
    for(const path of JSON.parse(process.argv[1])){files[path]=crypto.createHash('sha256').update(fs.readFileSync(path)).digest('hex');}
    const identity=pid=>{const stat=fs.readFileSync('/proc/'+pid+'/stat').toString();return {pid,start_time:stat.slice(stat.lastIndexOf(')')+2).trim().split(/\s+/)[19],command:fs.readFileSync('/proc/'+pid+'/cmdline').toString()};};
    const nodes=fs.readdirSync('/proc').filter(name=>Number.isInteger(+name)).flatMap(pid=>{try{const row=identity(pid);return row.command==='node\0index.js\0'?[row]:[]}catch{return []}});
    console.log(JSON.stringify({files,identity:{init:identity('1'),nodes},memory_events:fs.readFileSync('/sys/fs/cgroup/memory.events').toString(),pids_events:fs.readFileSync('/sys/fs/cgroup/pids.events').toString()}));
    '''
    data = json.loads(execute('target', 'node', '-e', script, json.dumps(list(profiles[version]['files_sha256']))))
    assert data['files'] == profiles[version]['files_sha256']
    assert len(data['identity']['nodes']) == 1
    assert all(int(line.split()[1]) == 0 for line in data['memory_events'].splitlines())
    assert data['pids_events'].strip() == 'max 0'
    return data


def database_state():
    script = r'''
    const sqlite=require('sqlite3');const db=new sqlite.Database('/config/absdatabase.sqlite',sqlite.OPEN_READONLY);
    const all=sql=>new Promise((resolve,reject)=>db.all(sql,(error,rows)=>error?reject(error):resolve(rows)));
    (async()=>{const tables=await all("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name");
      const users=(await all('SELECT * FROM users')).map(row=>Object.fromEntries(['id','username','type','isActive','isLocked','permissions','createdAt'].filter(key=>key in row).map(key=>[key,row[key]])));
      const libraries=(await all('SELECT * FROM libraries')).map(row=>Object.fromEntries(['id','name','mediaType','displayOrder','settings','createdAt'].filter(key=>key in row).map(key=>[key,row[key]])));
      console.log(JSON.stringify({tables,users,libraries}));db.close();})().catch(error=>{console.error(error);db.close();process.exitCode=1;});
    '''
    data = json.loads(execute('target', 'node', '-e', script))
    assert {'users', 'libraries'} <= {row['name'] for row in data['tables']}
    if initialized:
        assert len(data['users']) == len(data['libraries']) == 1
        assert data['users'][0]['username'] == 'module-root' and data['users'][0]['type'] == 'root'
        assert data['libraries'][0]['name'] == 'Module Target Library'
    else:
        assert data['users'] == data['libraries'] == []
    return data


try:
    if not runtime.get('native_only'):
        pg = ['psql', '-h', '127.0.0.1', '-U', 'module_framework', '-d', 'module_targets', '-v', 'ON_ERROR_STOP=1', '-Atc']
        result['postgres_version'] = execute('reporting_db', 'env', 'PGPASSWORD=module-target-framework-db-password', *pg, 'SELECT version()').decode().strip()
        assert not execute('reporting_db', 'env', 'PGPASSWORD=module-target-rejected-password', *pg, 'SELECT 1', expected=2)
    if profile == 'unrelated':
        status, body, _ = request('/')
        assert status == 200 and b'It works!' in body
        result['ordinary_sha256'] = hashlib.sha256(body).hexdigest()
        assert request('/status')[0] == request('/api/libraries')[0] == 404
        result['identity'] = execute('target', 'cat', '/proc/1/stat').decode().split(') ', 1)[1].split()[19]
    else:
        before = target_state()
        status, _, data = request('/status')
        assert status == 200 and data['app'] == 'audiobookshelf' and data['serverVersion'] == version
        if initialized and phase == 'before':
            assert data['isInit'] is False
            assert request('/init', 'POST', {'newRoot': {'username': 'module-root', 'password': 'module-target-audiobookshelf-password'}})[0] == 200
        status, _, data = request('/status')
        assert data['isInit'] is initialized
        result['server_status'] = data
        if initialized:
            assert request('/login', 'POST', {'username': 'module-root', 'password': 'module-target-rejected-password'})[0] == 401
            status, _, login = request('/login', 'POST', {'username': 'module-root', 'password': 'module-target-audiobookshelf-password'})
            assert status == 200 and login['user']['type'] == 'root'
            token = login['user']['token']
            result['root_token'] = token
            if phase == 'before':
                assert request('/api/libraries', 'POST', {'name': 'Module Target Library', 'folders': [{'fullPath': '/audiobooks'}], 'mediaType': 'book'}, token=token)[0] == 200
            status, _, libraries = request('/api/libraries', token=token)
            assert status == 200 and len(libraries['libraries']) == 1
            assert libraries['libraries'][0]['name'] == 'Module Target Library'
            result['authenticated_libraries'] = libraries['libraries']
        result['database'] = database_state()
        for base in ['', prefix]:
            assert request(base + '/api/libraries')[0] == 401
            assert request(base + '/api/libraries', token='module-target-invalid-token')[0] == 401
            assert request(base + '/api/libraries?r=%2Fapi%2Fitems%2F1%2Fcover')[0] == 401
            assert request(base + '/api/libraries?r=/module-target-unrelated')[0] == 401
            status, body, _ = request(base + '/api/libraries?r=/api/items/1/cover')
            assert status == (401 if profile == 'fixed' else 500)
            if profile != 'fixed':
                assert b'Internal Server Error' in body
            assert request('/healthcheck')[0] == 200
            assert request(base + '/api/module-target-route-control')[0] == 401
            assert request(base + '/api/module-target-route-control?r=/api/items/1/cover')[0] == (401 if profile == 'fixed' else 404)
        after = target_state()
        assert before['identity'] == after['identity']
        assert database_state() == result['database']
        result.update(files=after['files'], identity=after['identity'], memory_events=after['memory_events'], pids_events=after['pids_events'])
        assert request('/healthcheck')[0] == 200
    result['status'] = 'native_passed'
except (AssertionError, OSError, ValueError, KeyError, subprocess.SubprocessError, http.client.HTTPException) as error:
    result.update(status='native_failed', error=str(error))
    raise
finally:
    Path(runtime['artifacts'], 'native-' + phase + '.json').write_text(json.dumps(result, indent=2) + '\n')
