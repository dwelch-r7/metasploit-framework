"""Decode an owner-issued cookie with the installed application, optionally use it."""
import base64
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / 'superset'))
from native_http import NativeHTTP


runtime = json.loads(Path(sys.argv[1]).read_text())
mode, cookie = sys.argv[2:]
assert mode in ['literal', 'identity']
artifacts = Path(runtime['artifacts']) / ('owner-cookie-' + mode)
artifacts.mkdir()
native = NativeHTTP(runtime['compose'], 'http://127.0.0.1:' + str(runtime['endpoints']['gateway']['port']), artifacts)
result = {}
try:
    result['decoded'] = native.app('decode', cookie=cookie)['decoded']
    if mode == 'identity':
        browser, _ = native.browser()
        status, body = native.request(browser, '/api/v1/me/', cookie=cookie)
        result.update(status=status, body_base64=base64.b64encode(body).decode())
    else:
        result['identity_request'] = 'Not executed: legacy literal data is not a standard Flask session mapping'
finally:
    native.save()
    (artifacts / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
