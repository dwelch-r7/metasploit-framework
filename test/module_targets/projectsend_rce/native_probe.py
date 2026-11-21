"""Independent stock PHP producer and genuine client/upload lifecycle controls."""

from pathlib import Path
import base64
import hashlib
import json
import os
import re
import subprocess
import sys
import urllib.parse
import urllib.request

sys.path.insert(0, str(Path('test/module_targets/projectsend').resolve()))
from native_probe import Inputs, Native


class UploadControl(Native):
    def sql(self, query, values=()):
        code = '$cfg="/app/www/public/includes/sys.config.php";require $cfg;$db=new PDO("mysql:host=".DB_HOST.";dbname=".DB_NAME.";charset=utf8mb4",DB_USER,DB_PASSWORD,[PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION,PDO::ATTR_DEFAULT_FETCH_MODE=>PDO::FETCH_ASSOC]);$q=$db->prepare($argv[1]);$q->execute(json_decode($argv[2],true,512,JSON_THROW_ON_ERROR));echo json_encode($q->fetchAll(),JSON_THROW_ON_ERROR);'
        return json.loads(self.command('native-sql', 'php83', '-r', code, query, json.dumps(values), user=1000))

    def physical(self, path):
        assert path.startswith('/app/www/public/upload/files/') and re.fullmatch('[a-zA-Z0-9_.-]+', Path(path).name)
        code = '$p=$argv[1];echo json_encode(file_exists($p)?["exists"=>true,"uid"=>fileowner($p),"base64"=>base64_encode(file_get_contents($p))]:["exists"=>false],JSON_THROW_ON_ERROR);'
        return json.loads(self.command('physical-upload', 'php83', '-r', code, path, user=1000))

    def token(self, path):
        response = self.request('GET', path)
        assert response['status'] == 200, response
        parser = Inputs()
        parser.feed(base64.b64decode(response['body_base64']).decode())
        value = parser.inputs['csrf_token']
        assert re.fullmatch('[a-f0-9]{64}', value)
        return value

    def multipart(self, label, source, filename):
        request = urllib.request.Request(self.base + 'includes/upload.process.php')
        self.jar.add_cookie_header(request)
        cookie = request.get_header('Cookie')
        assert cookie
        # Curl receives the resolved HTTP Cookie header: an exported blank
        # expiry field silently drops this application's session cookie.
        argv = ['curl', '--silent', '--show-error', '--noproxy', '*', '--header', 'Cookie: ' + cookie,
                '--dump-header', str(self.directory / (label + '.headers')),
                '--output', str(self.directory / (label + '.body')), '--write-out', '%{http_code}',
                '--form', 'name=' + filename,
                '--form', 'file=@' + str(source) + ';type=application/octet-stream;filename=native.bin',
                self.base + 'includes/upload.process.php']
        process = subprocess.run(argv, capture_output=True, text=True, timeout=30)
        response = dict(status=int(process.stdout) if process.returncode == 0 else None,
                        body=json.loads((self.directory / (label + '.body')).read_bytes()) if process.returncode == 0 else None)
        self.journal.setdefault('multipart', []).append(dict(argv=argv, exit=process.returncode, stderr=process.stderr, response=response))
        self.save()
        assert process.returncode == 0, process.stderr
        return response

    def snapshot(self):
        code = '$root="/app/www/public/upload/files/";$out=[];foreach(scandir($root)as$name){if($name==="."||$name===".."){continue;}$path=$root.$name;if(is_file($path)){$out[]=["name"=>$name,"uid"=>fileowner($path),"size"=>filesize($path),"sha256"=>hash_file("sha256",$path)];}}echo json_encode($out,JSON_THROW_ON_ERROR);'
        return dict(options=self.observe('options'),
                    users=self.sql('SELECT id,user,level,active,email FROM mcv_users ORDER BY id'),
                    files=self.sql('SELECT id,url,filename,uploader FROM mcv_files ORDER BY id'),
                    physical_uploads=json.loads(self.command('physical-upload-inventory', 'php83', '-r', code, user=1000)))

    def control(self, case):
        state = json.loads((Path(self.runtime['artifacts']) / 'projectsend-state.json').read_text())
        baseline = state['baseline']
        proof = case['proof']
        expected = dict(exists=True, uid=1000, base64=case['marker_base64'])
        program = base64.b64decode(case['program_base64']).decode()
        source = self.directory / 'stock-control.php'
        wrapped = '<?php @unlink(__FILE__);' + program + ' ?>'
        source.write_text(wrapped)
        filename = 'module-target-projectsend-native-' + str(os.getpid()) + '.php'
        username, password = 'nativeclient' + str(os.getpid()), 'Native-Client-42!'
        physical = None
        result = dict(module_invoked=False, application_source_changed=False,
                      producer='php/exec', program_sha256=hashlib.sha256(program.encode()).hexdigest())
        original_files = self.snapshot()['files']
        try:
            assert self.observe('options') == baseline
            assert self.file(proof) == dict(exists=False)
            self.command('stock-php-cli', 'php83', '-r', program, user=1000)
            assert self.file(proof) == expected
            assert self.file(proof, remove=True) == dict(exists=False)
            result['stock_cli_passed'] = True

            settings = dict(clients_can_register='1', clients_auto_approve='1', clients_can_upload='1', clients_can_delete_own_files='1')
            response = self.request('POST', 'options.php?section=branding', dict(csrf_token=self.csrf(), **settings))
            result['enable_status'] = response['status']
            values = {row['name']: row['value'] for row in self.observe('options')}
            assert all(values[key] == value for key, value in settings.items())
            response = self.request('POST', 'register.php', dict(csrf_token=self.token('register.php'), name='Native Client', username=username, password=password, email=username + '@example.test', address='Native fixture'))
            result['registration_status'] = response['status']
            users = self.sql('SELECT id,user,level,active FROM mcv_users WHERE user=?', [username])
            assert len(users) == 1 and str(users[0]['active']) == '1' and str(users[0]['level']) == '0', users
            result['registered_user'] = users[0]
            self.jar.clear()
            response = self.request('POST', 'index.php', dict(csrf_token=self.csrf(), do='login', username=username, password=password))
            assert response['status'] == 303 and 'my_files/index.php' in response['headers'].get('Location', ''), response
            assert self.request('GET', 'my_files/index.php')['status'] == 200

            denied = self.multipart('php-denied', source, filename)
            assert denied['status'] == 400 and denied['body']['OK'] == 0 and denied['body']['error']['message'] == 'Invalid Extension', denied
            assert self.snapshot()['files'] == original_files
            anonymous = Native(self.runtime, self.directory / 'anonymous-options')
            anonymous.request('POST', 'options.php?section=branding', dict(csrf_token=anonymous.csrf(), file_types_limit_to='noone'))
            assert next(row['value'] for row in self.observe('options') if row['name'] == 'file_types_limit_to') == 'noone'
            accepted = self.multipart('php-accepted', source, filename)
            assert accepted['status'] == 200 and accepted['body']['OK'] == 1, accepted
            identifier = int(accepted['body']['info']['id'])
            rows = self.sql('SELECT id,url,filename,uploader FROM mcv_files WHERE id=?', [identifier])
            assert len(rows) == 1
            result['uploaded_row'] = rows[0]
            basename = rows[0]['url']
            physical = '/app/www/public/upload/files/' + basename
            assert self.physical(physical) == dict(exists=True, uid=1000, base64=base64.b64encode(wrapped.encode()).decode())
            response = self.request('GET', 'upload/files/' + urllib.parse.quote(basename, safe=''))
            assert response['status'] == 200 and self.file(proof) == expected
            assert self.physical(physical) == dict(exists=False)
            result['exact_upload_and_web_proof'] = True

            response = self.request('POST', 'manage-files.php', {'csrf_token': self.token('manage-files.php'), 'action': 'delete', 'batch[]': str(identifier)})
            result['portal_delete_status'] = response['status']
            assert self.snapshot()['files'] == original_files
            result['portal_row_removed'] = True
            return result
        finally:
            # Explicit fixture recovery is recorded separately from both native
            # API cleanup and the later production module's untouched cleanup.
            result['state_before_fixture_recovery'] = self.snapshot()
            assert self.file(proof, remove=True) == dict(exists=False)
            if physical:
                self.command('fixture-remove-upload', 'rm', '-f', '--', physical, user=1000)
                assert self.physical(physical) == dict(exists=False)
            self.sql('DELETE FROM mcv_users WHERE user=?', [username])
            self.observe('restore-options', baseline)
            assert self.observe('options') == baseline
            result['fixture_options_restored'] = True
            self.journal['result'] = result
            self.save()


def main():
    runtime = json.loads(Path(os.environ['MODULE_TARGET_RUNTIME']).read_text())
    action, *arguments = sys.argv[1:]
    native = UploadControl(runtime, Path(runtime['artifacts']) / ('projectsend-upload-' + action + '-' + str(os.getpid())))
    try:
        if action == 'control':
            result = native.control(json.loads(Path(arguments[0]).read_text()))
        elif action == 'contain-mail':
            state_path = Path(runtime['artifacts']) / 'projectsend-state.json'
            state = json.loads(state_path.read_text())
            assert native.observe('options') == state['baseline']
            closed = '$errno=0;$message="";$s=@fsockopen("127.0.0.1",9,$errno,$message,0.5);if($s!==false){fclose($s);throw new RuntimeException("Mail containment port is open");}echo json_encode(["errno"=>$errno,"message"=>$message],JSON_THROW_ON_ERROR);'
            refusal = json.loads(native.command('mail-loopback-refusal', 'php83', '-r', closed, user=1000))
            assert refusal['errno'] == 111, refusal
            settings = dict(mail_system_use='smtp', mail_smtp_host='127.0.0.1', mail_smtp_port='9', mail_smtp_auth='none')
            native.observe('set-options', settings)
            baseline = native.observe('options')
            expected = [dict(row, value=settings[row['name']]) if row['name'] in settings else row for row in state['baseline']]
            assert baseline == expected
            result = dict(before=state['baseline'], settings=settings, refusal=refusal, baseline=baseline)
            state['baseline'] = baseline
            state_path.write_text(json.dumps(state, indent=2) + '\n')
        elif action == 'state':
            result = native.snapshot()
        elif action == 'proof':
            result = native.file(arguments[0], remove=arguments[1:] == ['remove'])
        else:
            raise ValueError('Unsupported action')
        native.journal['result'] = result
        print(json.dumps(result))
    except Exception as error:
        native.journal['error'] = dict(type=type(error).__name__, message=str(error))
        raise
    finally:
        native.save()


if __name__ == '__main__':
    main()
