"""Read native state without overwriting the preflight transcripts."""

import json
import os
from client import InfluxTarget

api = InfluxTarget(json.loads(open(os.environ["MODULE_TARGET_RUNTIME"]).read()))
states = {service: api.state(service) for service in ["secured", "open", "empty"]}
print(json.dumps({"states": states, "requests": api.requests}))
