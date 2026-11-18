"""Keep the embedding interpreter alive after executing a real generated stager."""
import builtins
import json
import os
import sys

request = json.loads(sys.stdin.readline())
namespace = {}
failure = None
try:
    exec(request['stager'], namespace)
except RuntimeError as error:
    failure = {'type': type(error).__name__, 'message': str(error)}

print(json.dumps({
    'socket_closed': namespace['s'].fileno() == -1,
    'failure': failure,
}), flush=True)

# Retain the namespace/socket and process until Ruby observes peer EOF. Merely
# exiting this interpreter would hide a missing close in the generated stager.
sys.stdin.readline()
child = getattr(builtins, '_module_target_child', None)
if child:
    _, status = os.waitpid(child, 0)
    if status:
        raise RuntimeError('The stage child failed: ' + str(status))
