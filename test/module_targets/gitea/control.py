"""Expose existing native Gitea API controls to the Ruby acceptance family."""
import json
import sys
sys.dont_write_bytecode = True
from native_client import NativeGitea

request = json.loads(sys.argv[1]);native = NativeGitea();action = request['action'];service = request['service']
if action == 'http':
    credentials = native.admin if request.get('role', 'admin') == 'admin' else native.user
    status, document = native.request(service, request['route'], credentials, request.get('data'), request.get('method'))
    result = {'status': status, 'document': document}
elif action == 'grant':
    native.grant(service, request['allowed']);result = {'permission': request['allowed'], 'is_admin': False}
elif action == 'tree':
    result = native.tree(service)
else:
    raise ValueError('Unknown native control action')
print(json.dumps(result))
