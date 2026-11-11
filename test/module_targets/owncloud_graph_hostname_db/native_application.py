"""Observe the actual database endpoint through the genuine ownCloud connection."""
import base64
import json
from pathlib import Path
import subprocess
import sys

runtime = json.loads(Path(sys.argv[1]).read_text())
phase = sys.argv[2]
result = {'status': 'starting', 'phase': phase, 'commands': []}


def execute(script, user=None):
    argv = runtime['compose'] + ['exec', '-T']
    if user:
        argv += ['--user', user]
    argv += ['target', 'php', '-r', script]
    process = subprocess.run(argv, capture_output=True, timeout=60)
    row = {'argv': argv, 'exit': process.returncode,
           'stdout_base64': base64.b64encode(process.stdout).decode(),
           'stderr_base64': base64.b64encode(process.stderr).decode()}
    result['commands'].append(row)
    assert process.returncode == 0, row
    return json.loads(process.stdout)


try:
    result['server_overrides'] = execute(r'''
    $env=[];foreach(explode("\0",file_get_contents("/proc/1/environ")) as $entry){
      if(strpos($entry,"=")!==false){[$key,$value]=explode("=",$entry,2);$env[$key]=$value;}}
    $selected=[];foreach(["PGPORT","PGSERVICE","PGSERVICEFILE"] as $key){$selected[$key]=$env[$key]??null;}
    echo json_encode($selected);
    ''')
    result['application'] = execute(r'''
    define("OC_CONSOLE",true);
    require_once "/var/www/owncloud/lib/base.php";
    $config=\OC::$server->getConfig();
    $connection=\OC::$server->getDatabaseConnection();
    $row=$connection->fetchAssoc("SELECT inet_server_port() AS port, inet_server_addr() AS server_address, current_database() AS database, current_user AS username");
    $values=[];foreach(["dbtype","dbhost","dbname","dbuser"] as $key){$values[$key]=$config->getSystemValue($key);}
    echo json_encode(["configuration"=>$values,"connection"=>$row,"effective_uid"=>posix_geteuid(),"sapi"=>php_sapi_name()]);
    ''', user='www-data')
    app = result['application']
    assert app['configuration'] == {'dbtype': 'pgsql', 'dbhost': 'reporting_db',
                                    'dbname': 'owncloud', 'dbuser': 'module_framework'}
    assert app['effective_uid'] == 33 and app['sapi'] == 'cli'
    assert all(not value for value in result['server_overrides'].values())
    assert 1 <= int(app['connection']['port']) <= 65535
    assert app['connection']['database'] == 'owncloud'
    assert app['connection']['username'] == 'module_framework'
    result['status'] = 'application_port_verified'
except (AssertionError, OSError, ValueError, subprocess.SubprocessError) as error:
    result.update(status='native_failed', error=str(error))
    raise
finally:
    Path(runtime['artifacts'], 'native-application-' + phase + '.json').write_text(json.dumps(result, indent=2) + '\n')
