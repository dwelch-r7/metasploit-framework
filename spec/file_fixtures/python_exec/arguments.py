"""Run the real payload/parser; replace Popen only to inspect its arguments."""
import json
import subprocess
import sys
import threading

document = json.load(sys.stdin)
calls = []


class RecordedProcess(object):
    def communicate(self):
        return b'', b''


def capture(arguments, **options):
    calls.append({'arguments': arguments, 'options': options})
    return RecordedProcess()


subprocess.Popen = capture
baseline = set(threading.enumerate())
exec(compile(document['payload'], '<generated-python-exec>', 'exec'), {})
for worker in set(threading.enumerate()) - baseline:
    worker.join(5)
print(json.dumps(calls))
