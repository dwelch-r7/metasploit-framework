"""Exercise genuine Pi-hole authentication, gravity, SQLite and command output."""
import base64
import hashlib
import http.cookiejar
import json
from pathlib import Path
import re
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

runtime = json.loads(Path(sys.argv[1]).read_text())
profile, phase = sys.argv[2:4]
artifact = Path(runtime['artifacts'])
requests, commands = [], []
result = {'status': 'starting', 'profile': profile, 'phase': phase, 'requests': requests, 'commands': commands}
settings = json.loads((Path(__file__).parent / 'profiles.json').read_text())
vendor = settings['fixed' if profile == 'fixed' else 'vulnerable']
client = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
base = 'http://{host}:{port}'.format(**runtime['endpoints']['target'])


def execute(service, *argv, expected=0):
    started = time.monotonic()
    process = subprocess.run(runtime['compose'] + ['exec', '-T', service, *argv], capture_output=True, timeout=90)
    row = {'service': service, 'argv': argv, 'exitstatus': process.returncode, 'seconds': time.monotonic() - started,
           'stdout_base64': base64.b64encode(process.stdout).decode(), 'stderr_base64': base64.b64encode(process.stderr).decode()}
    commands.append(row)
    assert process.returncode == expected, row
    return process.stdout


def request(path, data=None):
    started = time.monotonic()
    payload = urllib.parse.urlencode(data).encode() if data is not None else None
    try:
        response = client.open(urllib.request.Request(base + path, data=payload), timeout=45)
    except urllib.error.HTTPError as error:
        response = error
    with response:
        body = response.read()
        status = response.status
    requests.append({'path': path, 'method': 'POST' if data is not None else 'GET', 'status': status,
                     'seconds': time.monotonic() - started, 'body_base64': base64.b64encode(body).decode()})
    return status, body


def gravity():
    status, body = request('/admin/scripts/pi-hole/php/gravity.sh.php')
    assert status == 200 and b'Number of gravity domains: 1' in body
    assert b'Unable to build gravity tree' not in body and b'DNS service is listening' in body
    return body


def api_settings(domains):
    status, body = request('/admin/settings.php?tab=api')
    assert status == 200
    match = re.search(rb'div id="token" hidden>([\w+=/]+)</div>|name="token" value="([\w+=/]+)">', body)
    assert match
    token = next(value for value in match.groups() if value).decode()
    status, body = request('/admin/settings.php?tab=api', {'domains': domains, 'clients': '', 'querylog-permitted': 'on',
                                                         'querylog-blocked': 'on', 'field': 'API', 'token': token})
    assert status == 200
    return body


def database():
    script = r'''
    $db=new SQLite3('/etc/pihole/gravity.db',SQLITE3_OPEN_READONLY);$data=[];
    foreach(['tables'=>"SELECT name FROM sqlite_master WHERE type='table' ORDER BY name",
      'adlists'=>"SELECT id,address,enabled FROM adlist ORDER BY id",
      'gravity'=>"SELECT domain,adlist_id FROM gravity ORDER BY domain",
      'domainlist'=>"SELECT type,domain,enabled FROM domainlist ORDER BY id"] as $key=>$sql){
      $res=$db->query($sql);if(!$res){exit(2);}$data[$key]=[];
      while($row=$res->fetchArray(SQLITE3_ASSOC)){$data[$key][]=$row;}}
    echo json_encode($data);
    '''
    data = json.loads(execute('target', 'php', '-r', script))
    assert len(data['adlists']) == len(data['gravity']) == 1 and data['domainlist'] == []
    assert data['adlists'][0]['address'] == 'http://127.0.0.1/module-target-blocklist.txt' and data['adlists'][0]['enabled'] == 1
    assert data['gravity'][0] == {'domain': 'blocked.module-target.invalid', 'adlist_id': data['adlists'][0]['id']}
    return data


try:
    pg = ['psql', '-h', '127.0.0.1', '-U', 'module_framework', '-d', 'module_targets', '-v', 'ON_ERROR_STOP=1', '-Atc']
    result['postgres_version'] = execute('reporting_db', 'env', 'PGPASSWORD=module-target-framework-db-password', *pg, 'SELECT version()').decode().strip()
    assert not execute('reporting_db', 'env', 'PGPASSWORD=module-target-rejected-password', *pg, 'SELECT 1', expected=2)
    if profile == 'unrelated':
        status, body = request('/')
        assert status == 200 and b'It works!' in body
        result['ordinary_sha256'] = hashlib.sha256(body).hexdigest()
        assert request('/admin/index.php')[0] == 404
        result['identity'] = execute('target', 'cat', '/proc/1/stat').decode().split(') ', 1)[1].split()[19]
    else:
        result['identity'] = execute('target', 'cat', '/proc/1/stat').decode().split(') ', 1)[1].split()[19]
        result['files'] = {}
        for line in execute('target', 'sha256sum', *vendor['files_sha256']).decode().splitlines():
            digest, path = line.split('  ', 1)
            result['files'][path] = digest
        assert result['files'] == vendor['files_sha256']
        # Cold disposable configuration can omit the web component from this
        # historical cache. Generate it using the vendor's local maintenance API.
        execute('target', 'pihole', 'updatechecker', 'local')
        cached = execute('target', 'cat', '/etc/pihole/localversions').decode().split()
        assert len(cached) == 3
        result['version_cache'] = [cached[0].split('-', 1)[0], cached[1].split('-', 1)[0], cached[2]]
        assert result['version_cache'] == [vendor['core_tag'], 'v' + vendor['web_version'], 'v' + vendor['ftl_version']]
        if phase == 'before':
            execute('target', 'php', '-r', "file_put_contents('/etc/pihole/adlists.list', \"http://127.0.0.1/module-target-blocklist.txt\\n\");")
            # Newer images ship a gravity database; older images migrate adlists.list.
            execute('target', 'php', '-r', r'''
            if(file_exists('/etc/pihole/gravity.db')){
              $db=new SQLite3('/etc/pihole/gravity.db',SQLITE3_OPEN_READWRITE);
              $count=$db->querySingle('SELECT count(*) FROM adlist');if($count>1){exit(2);}
              $sql=$count==0?"INSERT INTO adlist(address,enabled) VALUES ('http://127.0.0.1/module-target-blocklist.txt',1)":
                "UPDATE adlist SET address='http://127.0.0.1/module-target-blocklist.txt',enabled=1";
              if(!$db->exec($sql)){exit(3);}
            }
            ''')
        assert request('/module-target-blocklist.txt')[1] == b'0.0.0.0 blocked.module-target.invalid\n'
        status, body = request('/admin/index.php')
        assert status == 200
        status, body = request('/admin/settings.php?tab=api')
        assert status == 200
        if profile != 'noauth':
            assert b'Sign in to start your session' in body
            assert request('/admin/scripts/pi-hole/php/gravity.sh.php')[1] == b'Not authorized'
            status, body = request('/admin/index.php?login', {'pw': 'module-target-rejected-password'})
            assert status == 200 and b'Sign in to start your session' in body
            status, body = request('/admin/index.php?login', {'pw': 'module-target-pihole-password'})
            assert status == 200 and b'Sign in to start your session' not in body
        else:
            assert b'Sign in to start your session' not in body
        # A rejected domain still saves valid query preferences. Initialize them
        # through the real API so their first save cannot mimic an injection.
        assert b'The API settings have been updated' in api_settings('')
        gravity()
        # Older images return a truncated HTTP 200 page until gravity.db exists.
        # Accept the version page only after the real gravity pipeline succeeds.
        status, body = request('/admin/index.php')
        assert status == 200 and ('v' + vendor['web_version']).encode() in body
        assert b'Error connecting to database' not in body
        original = execute('target', 'cat', '/etc/pihole/setupVars.conf')
        result['config_base64'] = base64.b64encode(original).decode()
        result['oracles'] = {name: execute('target', name).decode().strip() for name in ['id', 'whoami']}
        for name in ['id', 'pwd'] if profile != 'fixed' else ['id']:
            body = api_settings('*;' + name)
            changed = execute('target', 'cat', '/etc/pihole/setupVars.conf')
            if profile == 'fixed':
                assert b'entry *;id is invalid' in body and changed == original
                assert result['oracles']['id'].encode() not in gravity()
            else:
                assert b'The API settings have been updated' in body and ('API_EXCLUDE_DOMAINS=*;' + name).encode() in changed
                output = gravity()
                if name == 'id':
                    assert ('data: ' + result['oracles']['id']).encode() in output
                else:
                    result['oracles']['pwd'] = output.splitlines()[0].decode().removeprefix('data: ')
                    assert result['oracles']['pwd'] == '/var/www/html/admin/scripts/pi-hole/php'
            execute('target', 'php', '-r', "file_put_contents('/etc/pihole/setupVars.conf',base64_decode($argv[1]));", result['config_base64'])
            assert execute('target', 'cat', '/etc/pihole/setupVars.conf') == original
        result['database'] = database()
        dns = execute('target', 'dig', '+norecurse', '+retry=0', '+time=1', '@127.0.0.1', 'pi.hole').decode()
        assert 'status: NOERROR' in dns and re.search(r'pi\.hole\.\s+\d+\s+IN\s+A\s+127\.0\.0\.1', dns)
        result['dns_control'] = dns
        result['limits'] = execute('target', 'sh', '-c', 'cat /sys/fs/cgroup/memory.events; cat /sys/fs/cgroup/pids.events').decode()
        assert all(int(line.split()[1]) == 0 for line in result['limits'].splitlines())
        assert execute('target', 'cat', '/proc/1/stat').decode().split(') ', 1)[1].split()[19] == result['identity']
    result['status'] = 'native_passed'
except (AssertionError, OSError, ValueError, KeyError, subprocess.SubprocessError, urllib.error.URLError) as error:
    result.update(status='native_failed', error=str(error))
    raise
finally:
    (artifact / ('native-' + phase + '.json')).write_text(json.dumps(result, indent=2) + '\n')
