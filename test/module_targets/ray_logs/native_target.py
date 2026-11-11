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
