"""Run the real payload/parser; replace Popen only to inspect its arguments."""
import json
import subprocess
import sys
import threading
import zlib

document = json.load(sys.stdin)
calls = []


if document.get('python2_ascii_decode'):
    # Model only Python 2's str.decode() default. The real decompressor and
    # codec implementation still run; this is not a Python 2 interpreter.
    class AsciiDefaultBytes(bytes):
        def decode(self, encoding='ascii', errors='strict'):
            return bytes.decode(self, encoding, errors)

    original_decompress = zlib.decompress

    def decompress(*arguments, **options):
        return AsciiDefaultBytes(original_decompress(*arguments, **options))

    zlib.decompress = decompress


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
