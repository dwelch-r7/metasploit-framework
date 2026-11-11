"""Real filesystem fixtures and installed Ray State API SDK controls."""
import base64
import hashlib
import json
import os
from pathlib import Path
import sys
from ray.util.state import list_logs, get_log

options = json.loads(sys.argv[1])
action = options['action']
log_dir = Path('/tmp/ray/session_latest/logs').resolve(strict=True)


def rejected_patterns(fixture):
    patterns = {name: item['glob'] for name, item in fixture['patterns'].items() if name != 'ordinary'}
    patterns['absolute'] = str(Path(fixture['root']) / 'outside/plain.txt')
    return patterns


def grpc_controls(fixture):
    import grpc
    from ray._common.network_utils import build_address
    from ray._private import ray_constants
    from ray._private.grpc_utils import init_grpc_channel
    from ray._private.services import canonicalize_bootstrap_address_or_die
    from ray._raylet import GcsClient
    from ray.core.generated.reporter_pb2 import ListLogsRequest
    from ray.core.generated.reporter_pb2_grpc import LogServiceStub
    from ray.dashboard import consts

    # Resolve the actual registered agent exactly as StateDataSourceClient does.
    gcs = GcsClient(address=canonicalize_bootstrap_address_or_die('auto'))
    address = gcs.internal_kv_get(
        (consts.DASHBOARD_AGENT_ADDR_NODE_ID_PREFIX + fixture['node_id']).encode(),
        namespace=ray_constants.KV_NAMESPACE_DASHBOARD, timeout=10)
    ip, http_port, grpc_port = json.loads(address)
    records = []
    with init_grpc_channel(build_address(ip, grpc_port), options=ray_constants.GLOBAL_GRPC_OPTIONS) as channel:
        stub = LogServiceStub(channel)
        ordinary = stub.ListLogs(ListLogsRequest(glob_filter=Path(fixture['log_file']).name), timeout=10)
        assert list(ordinary.log_files) == [Path(fixture['log_file']).name]
        for name, pattern in rejected_patterns(fixture).items():
            try:
                stub.ListLogs(ListLogsRequest(glob_filter=pattern), timeout=10)
            except grpc.RpcError as error:
                expected = f"Invalid glob filter: {pattern}. It must be a relative path and cannot contain '..'."
                assert error.code() == grpc.StatusCode.INVALID_ARGUMENT and error.details() == expected
                records.append({'name': name, 'glob': pattern, 'code': error.code().name, 'details': error.details()})
            else:
                raise AssertionError('Agent accepted an outside glob: ' + pattern)
    return {'agent': [ip, http_port, grpc_port], 'ordinary_log_files': list(ordinary.log_files), 'denials': records}


if action == 'seed':
    nonce = options['nonce']
    root = Path('/tmp/module-target-ray-logs-' + nonce)
    assert not root.exists()
    outside = root / 'outside'
    outside.mkdir(parents=True)
    files = {'plain.txt': b'Ray outside fixture\n', "space 'quoted' café #%.txt": 'UTF8 café\n'.encode(),
             'literal %2f.log': b'Literal percent\n', 'empty.txt': b'',
             'pattern?.log': b'Question\n', 'patternX.log': b'Wildcard\n'}
    for name, raw in files.items():
        (outside / name).write_bytes(raw)
    (outside / 'nested').mkdir()
    (outside / 'nested/child.log').write_bytes(b'Nested\n')
    log_file = log_dir / ('module-target-' + nonce + '.log')
    assert not log_file.exists()
    log_bytes = ('Owned Ray log ' + nonce + ' café\n').encode()
    log_file.write_bytes(log_bytes)
    prefix = '../' * 10
    pattern_root = prefix + str(outside).lstrip('/') + '/'
    patterns = {
        'ordinary': {'glob': log_file.name, 'expected': [str(log_file)]},
        'quoted': {'glob': pattern_root + "space 'quoted' café #%.txt", 'expected': [str(outside / "space 'quoted' café #%.txt")]},
        'percent': {'glob': pattern_root + 'literal %2f.log', 'expected': [str(outside / 'literal %2f.log')]},
        'all': {'glob': pattern_root + '*', 'expected': sorted([str(outside / name) for name in files] + [str(outside / 'nested') + '/'])},
        'wildcard': {'glob': pattern_root + 'pattern?.log', 'expected': sorted([str(outside / 'pattern?.log'), str(outside / 'patternX.log')])},
        'literal_question': {'glob': pattern_root + 'pattern[?].log', 'expected': [str(outside / 'pattern?.log')]},
        'empty': {'glob': pattern_root + 'empty.txt', 'expected': [str(outside / 'empty.txt')]},
        'missing': {'glob': pattern_root + 'absent-*', 'expected': []},
        'check': {'glob': prefix + 'etc/passw?', 'expected': ['/etc/passwd']}}
    records = []
    for path in [log_file] + sorted(root.rglob('*')):
        if path.is_file():
            records.append({'path': str(path), 'sha256': hashlib.sha256(path.read_bytes()).hexdigest(), 'size': path.stat().st_size, 'uid': path.stat().st_uid})
    result = {'root': str(root), 'log_dir': str(log_dir), 'log_file': str(log_file),
              'log_base64': base64.b64encode(log_bytes).decode(), 'files': records, 'patterns': patterns,
              'node_id': options['node_id'], 'uid': os.getuid(), 'gid': os.getgid()}
elif action == 'sdk':
    fixture = options['fixture']
    records = []
    for name, item in fixture['patterns'].items():
        if options['policy'] == 'confined' and name != 'ordinary':
            continue
        value = list_logs(address='auto', node_id=fixture['node_id'], glob_filter=item['glob'], timeout=10)
        raw = value.get('internal', [])
        canonical = sorted(str((log_dir / entry.rstrip('/')).resolve()) + ('/' if entry.endswith('/') else '') for entry in raw)
        records.append({'name': name, 'groups': value, 'canonical': canonical})
        assert canonical == sorted(item['expected']), records[-1]
    chunks = list(get_log(address='auto', node_id=fixture['node_id'], filename=Path(fixture['log_file']).name, tail=-1, timeout=10))
    joined = ''.join(chunks).encode()
    assert joined == base64.b64decode(fixture['log_base64'])
    result = {'records': records, 'exact_owned_log_bytes': True, 'log_sha256': hashlib.sha256(joined).hexdigest()}
    if options['policy'] == 'confined':
        result['grpc'] = grpc_controls(fixture)
elif action == 'http_denials':
    # The HTTP layer emits a generic 500. Require the genuine head's precise
    # upstream gRPC error for every actual glob, rather than accepting any 500.
    path = log_dir / 'dashboard_StateHead.log'
    raw = path.read_bytes()
    text = raw.decode(errors='replace')
    messages = [f"Invalid glob filter: {pattern}. It must be a relative path and cannot contain '..'."
                for pattern in rejected_patterns(options['fixture']).values()]
    assert all(message in text for message in messages)
    assert 'StatusCode.INVALID_ARGUMENT' in text
    result = {'path': str(path), 'sha256': hashlib.sha256(raw).hexdigest(), 'exact_messages': messages,
              'grpc_status': 'INVALID_ARGUMENT'}
elif action == 'verify':
    fixture = options['fixture']
    for record in fixture['files']:
        path = Path(record['path'])
        assert path.is_file() and not path.is_symlink() and path.stat().st_uid == record['uid']
        assert hashlib.sha256(path.read_bytes()).hexdigest() == record['sha256']
    result = {'fixture_bytes_unchanged': True}
elif action == 'cleanup':
    fixture = options['fixture']
    root = Path(fixture['root'])
    assert root.parent == Path('/tmp') and root.name.startswith('module-target-ray-logs-')
    for record in fixture['files']:
        path = Path(record['path'])
        assert path == Path(fixture['log_file']) or root in path.parents
        assert not path.is_symlink()
        path.unlink()
    (root / 'outside/nested').rmdir()
    (root / 'outside').rmdir()
    root.rmdir()
    result = {'owned_fixture_paths_absent': not root.exists() and not Path(fixture['log_file']).exists()}
else:
    raise ValueError(action)
print('MODULE_TARGET_RAY_LOGS_JSON:' + json.dumps(result))
