"""Recorded ordinary API controls used for independent post-action assertions."""
import base64
import json
import os
from pathlib import Path
import sys
import uuid

sys.dont_write_bytecode = True
from native_adapter import NativeFlowise
from native_actions import PASSWORD, consumed_token_replay, login, restore_password, spool


def main():
    request = json.loads(sys.argv[1])
    runtime = json.loads(Path(os.environ['MODULE_TARGET_RUNTIME']).read_text())
    native = NativeFlowise.attach(runtime, os.environ['FLOWISE_PROFILE'], uuid.uuid4().hex)
    try:
        action = request['action']
        if action == 'login':
            status, body, _ = login(native, request.get('password', PASSWORD))
            result = {'status': status, 'body_base64': base64.b64encode(body).decode()}
        elif action == 'restore':
            result = restore_password(native)
        elif action == 'consumed_replay':
            result = consumed_token_replay(native, request['email'], request['token'], request['current_password'])
        elif action in ['state', 'restore_state']:
            from native_state import STATE_SCRIPT
            operation = "console.log(JSON.stringify(snapshot()));" if action == 'state' else "console.log(JSON.stringify(restore(JSON.parse(process.argv[1]))));"
            arguments = [] if action == 'state' else [json.dumps(request['before'])]
            result = json.loads(native.cli('app', 'node', '-e', STATE_SCRIPT + operation, *arguments)['stdout'])
        elif action == 'request':
            status, body = native.request(request['path'], request.get('data'), method=request.get('method'))
            result = {'status': status, 'body_base64': base64.b64encode(body).decode()}
        elif action == 'spool':
            result = {'message_base64': base64.b64encode(spool(native).encode()).decode()}
        else:
            raise ValueError('Unsupported native action: ' + action)
        print(json.dumps(result))
    finally:
        native.save()


if __name__ == '__main__':
    main()
