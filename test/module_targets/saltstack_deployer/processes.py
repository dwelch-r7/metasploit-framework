"""Read process birth identity so PID reuse cannot impersonate a live payload."""
import base64
import json
from pathlib import Path
import sys

result = {}
for value in sys.argv[1:]:
    assert value.isdigit()
    process = Path('/proc') / value
    try:
        fields = (process / 'stat').read_text().split(') ', 1)[1].split()
        result[value] = {'state': fields[0], 'starttime': fields[19],
                         'uid': process.stat().st_uid,
                         'command_base64': base64.b64encode((process / 'cmdline').read_bytes()).decode()}
    except (FileNotFoundError, ProcessLookupError):
        pass
print(json.dumps(result, sort_keys=True))
