"""Owned native operation for acceptance observers; no simulated responses."""
import json
import sys
from native_client import NativeGogs


def main():
    request = json.loads(sys.argv[1])
    native = NativeGogs()
    action = request['action']
    service = request['service']
    if action == 'state':
        result = native.state(service)
    elif action == 'processes':
        result = native.processes(service)
    elif action == 'refs':
        result = native.refs(service, request['owner'], request['name'])
    elif action == 'pull_state':
        result = native.pull_state(service, request['owner'], request['name'], request['number'], request['seed_refs'])
    elif action == 'seed':
        result = native.seed(service, request['name'], rebase=request.get('rebase', True))
    elif action == 'remove_repo':
        native.remove_repo(service, request['owner'], request['name'])
        result = {'removed': True}
    elif action == 'revoke':
        native.revoke_new_tokens(service, request['user'], request['before'])
        result = {'restored': True}
    elif action == 'grant':
        native.edit_user(service, request['user'], allow_git_hook=request['allowed'])
        result = {'set': request['allowed']}
    elif action == 'http':
        status, document = native.request(service, request['route'], user=request.get('user'),
                                           data=request.get('data'), method=request.get('method'), token=request.get('token'))
        result = {'status': status, 'document': document}
    else:
        raise ValueError('Unknown native action: '+action)
    print(json.dumps(result))


if __name__ == '__main__':
    main()
