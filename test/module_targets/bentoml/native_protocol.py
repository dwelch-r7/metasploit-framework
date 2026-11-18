"""Executed in the disposable app; native vendor protocol only, no Framework."""
from pathlib import Path
import base64
import hashlib
import importlib.metadata
import json
import os
import pickle
import sysconfig
import urllib.error
import urllib.request

report = {'owner_loaded': False, 'release': runtime['release'], 'mode': runtime['mode'], 'requests': [], 'cases': []}
base = 'http://127.0.0.1:' + str(runtime['port'])


def vendor_identity():
    site = Path(sysconfig.get_paths()['purelib'])
    expected = runtime['vendor_files']
    for name, digest in expected.items():
        assert hashlib.sha256((site / name).read_bytes()).hexdigest() == digest, name
    return {'version': importlib.metadata.version('bentoml'), 'python': __import__('platform').python_version(), 'uid': os.geteuid(), 'vendor_files_verified': len(expected), 'vendor_manifest_sha256': hashlib.sha256(json.dumps(expected, sort_keys=True).encode()).hexdigest()}


def request(label, path, data=None, headers=None):
    req = urllib.request.Request(base + path, data=data, headers={'User-Agent': 'bentoml-native-control', **(headers or {})})
    report['active_request'] = {'label': label, 'path': path, 'method': req.get_method()}
    try:
        response = urllib.request.urlopen(req, timeout=20)
    except urllib.error.HTTPError as error:
        response = error
    with response:
        body = response.read()
        status = response.code
        received_headers = dict(response.headers)
        content_type = response.headers.get('Content-Type', '')
        # Runner responses use Bento-Payload-Meta; request fields omit that prefix.
        payload_meta = response.headers.get('Bento-Payload-Meta', '{}')
    report['requests'].append({'label': label, 'path': path, 'method': req.get_method(), 'status': status, 'headers': received_headers, 'request_headers': headers, 'request_sha256': hashlib.sha256(data or b'').hexdigest(), 'request_base64': base64.b64encode(data).decode() if data else None, 'body_base64': base64.b64encode(body).decode()})
    report.pop('active_request', None)
    return status, body, content_type, payload_meta


def ordinary(label):
    if runtime['mode'] == 'api':
        status, body, _, _ = request(label, '/summarize', json.dumps({'texts': ['native-first', 'native-second']}).encode(), {'Content-Type': 'application/json'})
        assert status == 200 and json.loads(body) == ['native-first', 'native-second'], (label, status, body[:600])
    else:
        import numpy as np
        from bentoml._internal.runner.container import AutoContainer, NdarrayContainer, Payload
        value = np.array([-3, 4], dtype=np.int64)
        payload = NdarrayContainer.to_payload(value, 0)
        headers = {'args-number': '1', 'Content-Type': 'application/vnd.bentoml.pickled', 'Payload-Container': payload.container, 'Payload-Meta': json.dumps(payload.meta), 'Batch-Size': str(payload.batch_size)}
        status, body, content_type, metadata = request(label, '/', payload.data, headers)
        assert status == 200, (status, body[:600])
        result = AutoContainer.from_payload(Payload(body, json.loads(metadata), content_type.rsplit('.', 1)[-1]))
        assert result.tolist() == [3, 4], result
    report['cases'].append({'case': label, 'passed': True})


class Canary:
    def __init__(self, expression):
        self.expression = expression

    def __reduce__(self):
        return eval, (self.expression,)


try:
    before = vendor_identity()
    assert before['version'] == runtime['release'] and before['uid'] == runtime['uid']
    report['identity'] = before
    status, _, _, _ = request('ready-before', '/readyz')
    assert status == 200
    if runtime['mode'] == 'api':
        status, body, _, _ = request('openapi', '/docs.json')
        assert status == 200 and '/summarize' in json.loads(body)['paths']
    else:
        status, body, _, _ = request('metrics', '/metrics')
        assert status == 200 and b'bentoml_runner' in body
    ordinary('ordinary-before')
    for negative in [True, False]:
        label = ('wrong-header' if runtime['mode'] == 'api' else 'unrelated-path') if negative else 'pickle-canary'
        marker = Path('/tmp/module-target-bentoml-' + runtime['stamp'] + '-' + label)
        expected = ('bentoml-native-' + runtime['release'] + '-' + runtime['mode']).encode()
        assert not marker.exists()
        try:
            expression = "(__import__('pathlib').Path(" + repr(str(marker)) + ").write_bytes(bytes.fromhex(" + repr(expected.hex()) + ")),None)[1]"
            if runtime['mode'] == 'runner':
                expression = "(" + expression + ",__import__('numpy').array([-3,4],dtype='int64'))[1]"
            payload = pickle.dumps(Canary(expression), protocol=4)
            if runtime['mode'] == 'api':
                headers = {'Content-Type': 'application/json' if negative else 'application/vnd.bentoml+pickle'}
                path = '/summarize'
            else:
                headers = {'args-number': '1', 'Content-Type': 'application/vnd.bentoml.pickled', 'Payload-Container': 'NdarrayContainer', 'Payload-Meta': json.dumps({'format': 'default'}), 'Batch-Size': '-1'}
                path = '/module-target-no-such-method' if negative else '/'
            status, _, _, _ = request(label, path, payload, headers)
            if negative and runtime['mode'] == 'runner':
                assert status == 404, status
            if not negative and runtime['release'] == '1.4.8' and runtime['mode'] == 'api':
                assert status == 415, status
            observed = {'exists': marker.is_file(), 'uid': marker.stat().st_uid if marker.is_file() else None, 'base64': base64.b64encode(marker.read_bytes()).decode() if marker.is_file() else None}
            should_execute = not negative and runtime['release'] == '1.4.2'
            passed = observed == {'exists': True, 'uid': runtime['uid'], 'base64': base64.b64encode(expected).decode()} if should_execute else not observed['exists']
            report['cases'].append({'case': label, 'expected_execution': should_execute, 'observed': observed, 'passed': passed})
            assert passed, (label, observed)
        except BaseException:
            report['failed_operation_marker'] = {'path': str(marker), 'exists': marker.is_file(), 'uid': marker.stat().st_uid if marker.is_file() else None, 'base64': base64.b64encode(marker.read_bytes()).decode() if marker.is_file() else None}
            raise
        finally:
            marker.unlink(missing_ok=True)
            assert not marker.exists()
    ordinary('ordinary-after')
    status, _, _, _ = request('ready-after', '/readyz')
    assert status == 200
    report['identity_after'] = vendor_identity()
    assert report['identity_after'] == before
    report['packages'] = sorted({dist.metadata['Name'] + '==' + dist.version for dist in importlib.metadata.distributions(path=[sysconfig.get_paths()['purelib']])})
    report['native_passed'] = True
except BaseException as error:
    report['failure'] = {'type': type(error).__name__, 'message': str(error)}
    raise
finally:
    print('BENTOML_NATIVE_JSON=' + json.dumps(report), flush=True)
