"""Run the real payload/parser; replace Popen only to inspect its arguments."""
import json
import subprocess
import sys

document = json.loads(sys.stdin.buffer.read().decode('utf-8'))
calls = []


def capture(arguments, **options):
    calls.append({'arguments': arguments, 'options': options})


subprocess.Popen = capture
exec(compile(document['payload'], '<generated-python-exec>', 'exec'), {})
print(json.dumps(calls))
