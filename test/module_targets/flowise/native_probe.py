"""Compact native prerequisites; run only inside an explicitly approved project."""
import base64
import json
import os
from pathlib import Path
import sys

sys.dont_write_bytecode = True
from native_adapter import NativeFlowise
from native_actions import EMAIL, PASSWORD, command_control, identity, login, restore_password, sdk_control, smtp_control, persistence_control


def main():
    runtime = json.loads(Path(os.environ['MODULE_TARGET_RUNTIME']).read_text())
    native = NativeFlowise(runtime, os.environ['FLOWISE_PROFILE'])
    result = {'profile': native.profile, 'version': native.definition['version'], 'module_verdict': None}
    try:
        result['identity'] = identity(native)
        result['docker_exec_uid'] = native.cli('app', 'id', '-u')['stdout'].strip()
        result['actual_processes'] = native.cli('app', 'ps', '-o', 'pid,ppid,args')['stdout']
        if native.definition['smtp']:
            result['smtp'] = smtp_control(native)
        if native.definition['mode'] not in ['open', 'basic']:
            status, body = native.request('/api/v1/account/register', {'user': {'name': 'Module Native', 'email': EMAIL, 'credential': PASSWORD}})
            assert status in [200, 201], (status, body)
            assert login(native)[0] in [200, 201]
            result['wrong_password_status'] = login(native, 'FlowiseWrong!42')[0]
            assert result['wrong_password_status'] in [400, 401, 403, 404]
            result['fresh_login_proved'] = True
        result['persistence'] = persistence_control(native)
        result['sdk'] = sdk_control(native)
        result['uid'] = result['sdk']['uid']
        if native.definition['mode'] in ['open', 'basic']:
            result['direct'] = command_control(native, 'direct', True)
            result['js'] = command_control(native, 'js', True)
            if native.definition['mode'] == 'basic':
                status, _ = native.request('/api/v1/node-load-method/customMCP', {'loadMethod': 'listActions', 'inputs': {'mcpServerConfig': '{}'}}, headers={'x-request-from': 'internal'})
                assert status == 401
                result['basic_missing_denied'] = True
        elif native.definition['mode'] in ['jwt_smtp', 'fixed_smtp']:
            result['js'] = command_control(native, 'js', native.definition['mode'] == 'jwt_smtp')
            result['recovery'] = restore_password(native)
            body = json.loads(base64.b64decode(result['recovery']['response_base64']))
            leaked = isinstance(body, dict) and isinstance(body.get('user'), dict) and bool(body['user'].get('tempToken'))
            assert leaked == (native.definition['mode'] == 'jwt_smtp')
            result['reset_token_disclosed'] = leaked
        else:
            result['npx'] = command_control(native, 'npx', native.definition['mode'] == 'npx')
            result['database_identity'] = native.cli('reporting_db', 'env', 'PGPASSWORD=module-target-framework-db-password', 'psql', '-h', '127.0.0.1', '-U', 'module_framework', '-d', 'module_targets', '-Atc', 'SELECT current_user,current_database(),version()')['stdout']
            assert 'module_framework|module_targets|PostgreSQL 16.' in result['database_identity']
            rejected = native.cli('reporting_db', 'env', 'PGPASSWORD=module-target-rejected', 'psql', '-h', '127.0.0.1', '-U', 'module_framework', '-d', 'module_targets', '-Atc', 'SELECT current_user', check=False)
            assert rejected['exitstatus'] == 2 and 'password authentication failed' in rejected['stderr']
            result['database_rejected_password'] = rejected['exitstatus']
        result['counts'] = {'commands': len(native.commands), 'requests': len(native.requests)}
        native.artifacts.joinpath('native-flowise-proof.json').write_text(json.dumps(result, indent=2))
        print(json.dumps(result))
    finally:
        native.save()


if __name__ == '__main__':
    main()
