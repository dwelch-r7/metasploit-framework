"""Counterfactual registration using captured fields and original validation."""

from pathlib import Path
import importlib.util
import json
import os
import re
import sys

spec = importlib.util.spec_from_file_location('projectsend_registration_base', 'test/module_targets/projectsend_rce/native_probe.py')
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
runtime = json.loads(Path(os.environ['MODULE_TARGET_RUNTIME']).read_text())
case = json.loads(Path(sys.argv[1]).read_text())
assert set(case) == {'name', 'username', 'password', 'email', 'address'}
assert '_' in case['username']
valid = case['username'].replace('_', '.')
assert re.fullmatch('[a-zA-Z0-9.]{5,32}', valid)
native = module.UploadControl(runtime, Path(runtime['artifacts'])/'registration-control')
result = dict(module_invoked=False, application_source_changed=False, username=case['username'], changed_username=valid)
before = native.snapshot()
try:
    options = {row['name']:row['value'] for row in before['options']}
    assert [options[name] for name in ['mail_system_use', 'mail_smtp_host', 'mail_smtp_port']] == ['smtp', '127.0.0.1', '9']
    expected = json.loads(Path('test/module_targets/projectsend_registration/vendor-files.json').read_text())
    actual = {}
    for name in expected:
        actual[name] = native.command('vendor-'+Path(name).stem, 'sha256sum', '/app/www/public/'+name, user=1000).decode().split()[0]
    assert actual == expected
    result['vendor_files'] = actual
    code = 'require "/app/www/public/includes/Classes/Validation.php";$c=new ReflectionClass("ProjectSend\\Classes\\Validation");$o=$c->newInstanceWithoutConstructor();$m=$c->getMethod("alpha_or_dot");echo json_encode([$m->invoke($o,$argv[1]),$m->invoke($o,$argv[2])],JSON_THROW_ON_ERROR);'
    result['original_validation'] = json.loads(native.command('original-validation', 'php83', '-r', code, case['username'], valid, user=1000))
    assert result['original_validation'] == [False, True]
    assert not native.sql('SELECT id FROM mcv_users WHERE user IN (?,?)', [case['username'], valid])
    # Fixture setup is explicit and separate from the owning exploit.
    native.observe('set-options', dict(clients_can_register='1', clients_auto_approve='1'))
    result['cases'] = []
    for username in [case['username'], valid]:
        native.jar.clear()
        parameters = dict(case, username=username, csrf_token=native.token('register.php'))
        response = native.request('POST', 'register.php', parameters)
        rows = native.sql('SELECT id,user,active,level,email FROM mcv_users WHERE user=?', [username])
        result['cases'].append(dict(username=username, response=response, rows=rows))
        if username == case['username']:
            assert response['status'] == 303 and not rows and response['headers']['Location'].endswith('/register.php'), rows
        else:
            assert len(rows) == 1 and rows[0]['user'] == username and int(rows[0]['active']) == 1 and int(rows[0]['level']) == 0, rows
            # This old application can fail after committing the account.
            # Capture that result, then prove the credential through real login.
            assert response['status'] in [303, 500], response
            if response['status'] == 303:
                assert response['headers']['Location'].endswith('my_files/index.php'), response
            else:
                code = '$out=[];$files=new RecursiveIteratorIterator(new RecursiveDirectoryIterator("/config/log",FilesystemIterator::SKIP_DOTS));foreach($files as $file){if($file->isFile()){$out[$file->getPathname()]=base64_encode(substr(file_get_contents($file->getPathname()),-65536));}}echo json_encode($out,JSON_THROW_ON_ERROR);'
                result['post_persistence_error_logs'] = json.loads(native.command('registration-error-logs', 'php83', '-r', code, user=1000))
            native.jar.clear()
            login = native.request('POST', 'index.php', dict(csrf_token=native.csrf(), do='login', username=username, password=case['password']))
            result['login'] = login
            assert login['status'] == 303 and login['headers']['Location'].endswith('my_files/index.php'), login
    result['passed'] = True
finally:
    result['before_fixture_recovery'] = native.snapshot()
    native.sql('DELETE FROM mcv_users WHERE user=?', [valid])
    native.observe('restore-options', before['options'])
    result['restored'] = native.snapshot()
    assert result['restored'] == before
    native.journal['result'] = result
    native.save()
print(json.dumps(dict(passed=result.get('passed'), original_validation=result.get('original_validation'), module_invoked=False)))
