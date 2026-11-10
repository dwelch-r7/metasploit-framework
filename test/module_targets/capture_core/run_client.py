"""Run one genuine client with actual packet capture from its owned namespace."""
import json
import sys
sys.dont_write_bytecode = True
from native_client import NativeClients
request = json.loads(sys.argv[1])
client = NativeClients()
result = client.capture(request['label'], request['port'], request['service'], *request['argv'])
response = {'result': result, 'wire': json.loads((client.artifacts/(request['label']+'.wire.json')).read_text())}
(client.artifacts/(request['label']+'-client.json')).write_text(json.dumps(response, indent=2)+'\n')
print(json.dumps(response))
