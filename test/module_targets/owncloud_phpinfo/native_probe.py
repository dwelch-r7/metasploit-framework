"""Independent real ownCloud HTTP, filesystem, authentication and service controls."""
import base64
from phpinfo import PhpInfo, VARIABLES
import http.client
import json
from pathlib import Path
import subprocess
import sys

runtime = json.loads(Path(sys.argv[1]).read_text())
profile, phase = sys.argv[2:4]
prefix = '/owncloud' if profile == 'prefix' else ''
fixed = profile == 'fixed'
requests, commands = [], []
result = {'status': 'starting', 'profile': profile, 'phase': phase, 'prefix': prefix,
          'requests': requests, 'commands': commands}
suffixes = ['css', 'js', 'svg', 'gif', 'png', 'html', 'ttf', 'woff', 'ico', 'jpg',
            'jpeg', 'json', 'properties', 'min.map', 'js.map', 'auto.map']

def execute(service, *argv, expected=0, owner=False):
    args = runtime['compose'] + ['exec', '-T']
    if owner:
        console = runtime['console_command']
        args += ['--user', console[console.index('--user') + 1]]
    process = subprocess.run(args + [service, *argv], capture_output=True, timeout=60)
    row = {'service': service, 'argv': argv, 'owner': owner, 'exit': process.returncode,
           'stdout_base64': base64.b64encode(process.stdout).decode(),
           'stderr_base64': base64.b64encode(process.stderr).decode()}
    commands.append(row)
    assert process.returncode == expected, row
    return process.stdout


def request(path, method='GET', auth=None):
    endpoint = runtime['endpoints']['target']
    connection = http.client.HTTPConnection(endpoint['host'], endpoint['port'], timeout=20)
    headers = {'Host': 'localhost'}
    if auth:
        headers['Authorization'] = 'Basic ' + base64.b64encode(auth.encode()).decode()
    try:
        connection.request(method, path, headers=headers)
        response = connection.getresponse()
        body = response.read()
        row = {'method': method, 'path': path, 'authenticated': bool(auth), 'status': response.status,
               'headers': response.getheaders(), 'body_base64': base64.b64encode(body).decode()}
        requests.append(row)
        return response.status, body
    finally:
        connection.close()


try:
    pg_password = 'module-target-framework-db-password'
    pg_args = ['psql', '-h', '127.0.0.1', '-U', 'module_framework', '-d', 'module_targets',
               '-v', 'ON_ERROR_STOP=1', '-Atc']
    result['postgres_version'] = execute('reporting_db', 'env', 'PGPASSWORD=' + pg_password,
                                         *pg_args, 'SELECT version()').decode().strip()
    rejected = execute('reporting_db', 'env', 'PGPASSWORD=module-target-rejected-password',
                       *pg_args, 'SELECT 1', expected=2)
    assert not rejected
    if profile == 'unrelated':
        status, body = request('/')
        assert status == 200 and b'It works!' in body
        result['ordinary_http'] = {'status': status, 'body_base64': base64.b64encode(body).decode()}
        stat = execute('target', 'cat', '/proc/1/stat').decode()
        tail = stat[stat.rindex(')') + 2:].split()
        result['identity'] = {'pid': stat.split()[0], 'comm': stat[stat.index('(') + 1:stat.rindex(')')],
                              'start_time': tail[19]}
        for suffix in ['css', 'json']:
            status, body = request('/apps/graphapi/vendor/microsoft/microsoft-graph/tests/GetPhpInfo.php/.' + suffix)
            assert status == 404 and b'phpinfo()' not in body
    else:
        php = r'''
        $app="/var/www/owncloud/apps/graphapi";
        $serverEnv=[];foreach(explode("\0",file_get_contents("/proc/1/environ")) as $entry){
          if(strpos($entry,"=")!==false){[$key,$value]=explode("=",$entry,2);$serverEnv[$key]=$value;}}
        $config=[]; foreach(json_decode($argv[1]) as $key){$config[$key]=$serverEnv[$key]??"";}
        $files=[]; $iterator=new RecursiveIteratorIterator(new RecursiveDirectoryIterator($app,FilesystemIterator::SKIP_DOTS));
        foreach($iterator as $file){if($file->isFile()){$files[substr($file->getPathname(),strlen($app)+1)]=hash_file("sha256",$file->getPathname());}}
        ksort($files);$lines="";foreach($files as $path=>$digest){$lines.=$digest."  ".$path."\n";}
        $stat=file_get_contents("/proc/1/stat");$tail=preg_split('/\s+/',trim(substr($stat,strrpos($stat,")")+2)));
        $info=simplexml_load_file($app."/appinfo/info.xml");$test=$app."/vendor/microsoft/microsoft-graph/tests/GetPhpInfo.php";
        echo json_encode(["environment"=>$config,"graph_version"=>(string)$info->version,
          "test_file_sha256"=>is_file($test)?hash_file("sha256",$test):null,
          "app_tree_sha256"=>hash("sha256",$lines),"app_file_count"=>count($files),
          "identity"=>["pid"=>"1","comm"=>substr($stat,strpos($stat,"(")+1,strrpos($stat,")")-strpos($stat,"(")-1),"start_time"=>$tail[19]],
          "phpinfo_enabled"=>function_exists("phpinfo"),
          "memory_events"=>file_get_contents("/sys/fs/cgroup/memory.events"),
          "pids_events"=>file_get_contents("/sys/fs/cgroup/pids.events")]);
        '''
        state = json.loads(execute('target', 'php', '-r', php, json.dumps(VARIABLES)))
        result.update(state)
        environment = state['environment']
        assert state['graph_version'] == ('0.3.1' if fixed else '0.3.0')
        if fixed:
            expected_app = json.loads((Path(__file__).parent / 'profiles.json').read_text())['fixed_app']
            assert state['app_tree_sha256'] == expected_app['app_tree_sha256']
            assert state['app_file_count'] == expected_app['app_file_count']
        assert state['phpinfo_enabled']
        assert state['test_file_sha256'] == (None if fixed else '89769091f2f01307fece3134d723f4651df022d0a46d0757c8ae274f364167ce')
        assert all(int(row.split()[1]) == 0 for row in state['memory_events'].splitlines())
        assert state['pids_events'].strip() == 'max 0'
        result['owncloud_status'] = json.loads(execute('target', 'occ', 'status', '--output=json'))
        assert result['owncloud_status']['installed'] and result['owncloud_status']['versionstring'] == '10.12.1'
        result['app_list'] = json.loads(execute('target', 'occ', 'app:list', '--output=json'))
        status, body = request(prefix + '/status.php')
        assert status == 200 and json.loads(body)['versionstring'] == '10.12.1'
        username, password = environment['OWNCLOUD_ADMIN_USERNAME'], environment['OWNCLOUD_ADMIN_PASSWORD']
        for auth, expected in [(None, 401), (username + ':module-target-rejected-password', 401), (username + ':' + password, 207)]:
            status, body = request(prefix + '/remote.php/dav/files/' + username + '/', method='PROPFIND', auth=auth)
            assert status == expected, (profile, expected, status)
        result['owncloud_schema_tables'] = int(execute('reporting_db', 'env', 'PGPASSWORD=' + pg_password,
            'psql', '-h', '127.0.0.1', '-U', 'module_framework', '-d', 'owncloud', '-Atc',
            "SELECT count(*) FROM information_schema.tables WHERE table_schema='public'").strip())
        assert result['owncloud_schema_tables'] > 20
        result['redis_version'] = execute('redis', 'redis-server', '--version').decode().strip()
        assert execute('redis', 'redis-cli', '--no-auth-warning', '-a', 'module-target-redis-password', 'PING').strip() == b'PONG'
        denied = execute('redis', 'redis-cli', '--no-auth-warning', '-a', 'module-target-rejected-password', 'PING')
        assert b'NOAUTH' in denied or b'WRONGPASS' in denied
        path = prefix + '/apps/graphapi/vendor/microsoft/microsoft-graph/tests/GetPhpInfo.php'
        status, body = request(path)
        assert status in {301, 302} and b'phpinfo()' not in body
        result['suffixes'] = {}
        for suffix in suffixes:
            status, body = request(path + '/.' + suffix)
            parser = PhpInfo()
            parser.feed(body.decode('utf-8'))
            if fixed:
                assert b'phpinfo()' not in body and not parser.rows
            else:
                assert status == 200 and set(parser.rows) == set(VARIABLES)
                assert parser.rows == environment, (suffix, {key for key in VARIABLES if parser.rows.get(key) != environment[key]})
            result['suffixes'][suffix] = {'status': status, 'phpinfo': not fixed, 'environment': parser.rows}
        wrong = prefix + '/module-target-missing/apps/graphapi/vendor/microsoft/microsoft-graph/tests/GetPhpInfo.php/.css'
        status, body = request(wrong)
        assert b'phpinfo()' not in body
        result['addresses'] = json.loads(execute('framework', 'ruby', '-rjson', '-rsocket', '-e',
            'puts JSON.generate(%w[reporting_db redis].to_h { |name| [name, IPSocket.getaddress(name)] })', owner=True))
    endpoint = runtime['module_endpoints']['target']
    refused = execute('framework', 'ruby', '-rsocket', '-e',
        'begin; TCPSocket.new(ARGV[0], 1); abort "Unexpected listener"; rescue Errno::ECONNREFUSED; puts "refused"; end', endpoint['host'], owner=True)
    assert refused.strip() == b'refused'
    result['status'] = 'native_passed'
finally:
    Path(runtime['artifacts'], 'native-' + phase + '.json').write_text(json.dumps(result, indent=2) + '\n')
