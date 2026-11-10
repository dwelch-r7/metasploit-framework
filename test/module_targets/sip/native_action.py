"""Run one bounded native action for the acceptance fixtures."""
import json
import os
from pathlib import Path
import sys
from native_client import NativeSIP

runtime = json.loads(Path(os.environ['MODULE_TARGET_RUNTIME']).read_text())
client = NativeSIP(runtime)
action = json.load(sys.stdin)
kind = action.pop('action')
if kind == 'api':
    operations = action['operations']
    for operation in operations:
        if 'role' in operation:
            operation['host'] = client.ip(operation['role'])
    result = client.api(operations)
elif kind == 'state':
    result = client.state(action['service'])
elif kind == 'inactive':
    result = client.inactive(action['service'])
elif kind == 'wire':
    result = client.wire(**action)
elif kind == 'unregister':
    result = client.unregister(action['service'], action.get('account', '1000'))
elif kind == 'sipsak':
    result = client.sipsak(**action)
elif kind == 'sipp':
    result = client.sipp(host=client.ip(action.pop('service')), **action)
else:
    raise ValueError('Unknown native action: ' + kind)
print(json.dumps(result))
