"""Real multipart preparation and deletion for a stock web session control."""

from pathlib import Path
import base64
import importlib.util
import json
import os
import sys
import urllib.parse
import urllib.request

# Load under a distinct name: the reused upload observer imports its base
# native_probe module, which intentionally has the same filename.
spec = importlib.util.spec_from_file_location('projectsend_upload_control', 'test/module_targets/projectsend_rce/native_probe.py')
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


def prepare(native, program_file, context):
    state = json.loads((Path(native.runtime['artifacts']) / 'projectsend-state.json').read_text())
    before = native.snapshot()
    assert before['options'] == state['baseline']
    program = json.loads(Path(program_file).read_text())
    wrapped = '<?php @unlink(__FILE__);' + base64.b64decode(program['encoded']).decode() + ' ?>'
    source = native.directory / 'stock-session.php'
    source.write_text(wrapped)
    username, password = 'nativesession' + str(os.getpid()), 'Native-Session-42!'
    result = dict(module_invoked=False, username=username, password=password, baseline=before, program=program)
    context.write_text(json.dumps(result, indent=2) + '\n')
    settings = dict(clients_can_register='1', clients_auto_approve='1', clients_can_upload='1', clients_can_delete_own_files='1')
    response = native.request('POST', 'options.php?section=branding', dict(csrf_token=native.csrf(), **settings))
    result['enable_status'] = response['status']
    response = native.request('POST', 'register.php', dict(csrf_token=native.token('register.php'), name='Native Session', username=username, password=password, email=username + '@example.test', address='Native fixture'))
    result['register_status'] = response['status']
    users = native.sql('SELECT id,user,active,level FROM mcv_users WHERE user=?', [username])
    assert len(users) == 1 and int(users[0]['active']) == 1 and int(users[0]['level']) == 0
    native.jar.clear()
    response = native.request('POST', 'index.php', dict(csrf_token=native.csrf(), do='login', username=username, password=password))
    assert response['status'] == 303 and 'my_files/index.php' in response['headers'].get('Location', ''), response
    filename = 'module-target-projectsend-native-session-' + str(os.getpid()) + '.php'
    denied = native.multipart('session-denied', source, filename)
    assert denied['status'] == 400 and denied['body']['OK'] == 0 and denied['body']['error']['message'] == 'Invalid Extension'
    anonymous = module.Native(native.runtime, native.directory / 'anonymous-options')
    anonymous.request('POST', 'options.php?section=branding', dict(csrf_token=anonymous.csrf(), file_types_limit_to='noone'))
    accepted = native.multipart('session-accepted', source, filename)
    assert accepted['status'] == 200 and accepted['body']['OK'] == 1
    identifier = int(accepted['body']['info']['id'])
    rows = native.sql('SELECT id,url FROM mcv_files WHERE id=?', [identifier])
    assert len(rows) == 1
    physical = '/app/www/public/upload/files/' + rows[0]['url']
    assert native.physical(physical) == dict(exists=True, uid=1000, base64=base64.b64encode(wrapped.encode()).decode())
    result.update(file_id=identifier, physical=physical, url=native.base + 'upload/files/' + urllib.parse.quote(rows[0]['url'], safe=''), denied=denied, accepted=accepted)
    context.write_text(json.dumps(result, indent=2) + '\n')
    return result


def cleanup(native, context):
    data = json.loads(context.read_text())
    before = native.snapshot()
    if 'file_id' in data:
        assert native.physical(data['physical']) == dict(exists=False)
        native.jar.clear()
        response = native.request('POST', 'index.php', dict(csrf_token=native.csrf(), do='login', username=data['username'], password=data['password']))
        assert response['status'] == 303
        response = native.request('POST', 'manage-files.php', {'csrf_token': native.token('manage-files.php'), 'action': 'delete', 'batch[]': str(data['file_id'])})
        assert native.snapshot()['files'] == data['baseline']['files']
    # Account and configuration recovery here belongs to the independent
    # fixture, never to the production module's cleanup verdict.
    native.sql('DELETE FROM mcv_users WHERE user=?', [data['username']])
    native.observe('restore-options', data['baseline']['options'])
    restored = native.snapshot()
    assert restored == data['baseline']
    return dict(before_fixture_recovery=before, native_portal_cleanup=True, explicit_fixture_recovery=True, restored=restored)


def main():
    runtime = json.loads(Path(os.environ['MODULE_TARGET_RUNTIME']).read_text())
    action, *arguments = sys.argv[1:]
    native = module.UploadControl(runtime, Path(runtime['artifacts']) / ('projectsend-session-' + action + '-' + str(os.getpid())))
    context = Path(runtime['artifacts']) / 'projectsend-api-session-context.json'
    try:
        if action == 'prepare':
            result = prepare(native, arguments[0], context)
        elif action == 'trigger':
            data = json.loads(context.read_text())
            with urllib.request.urlopen(data['url'], timeout=180) as response:
                result = dict(code=response.status, body_base64=base64.b64encode(response.read()).decode())
            assert result['code'] == 200
        elif action == 'cleanup':
            result = cleanup(native, context)
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
