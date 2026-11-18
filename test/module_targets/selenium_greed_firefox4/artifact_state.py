from pathlib import Path
import base64
import hashlib
import json
import os
import sys

roots = sorted(set([Path('/home/seluser/Downloads'), *Path('/tmp').glob('mozilla_*')]))

def snapshot():
    data = {'files': {}, 'directories': {}, 'processes': {}}
    for root in roots:
        data['directories'][str(root)] = {'exists': root.exists()}
        if not root.exists():
            continue
        assert root.is_dir() and not root.is_symlink()
        for path in [root, *root.rglob('*')]:
            assert not path.is_symlink(), str(path)
            stat = path.stat()
            if path.is_dir():
                data['directories'][str(path)] = {'exists': True, 'uid': stat.st_uid, 'mode': oct(stat.st_mode & 0o777)}
            elif path.is_file():
                assert stat.st_size < 524288, str(path)
                raw = path.read_bytes()
                data['files'][str(path)] = {'sha256': hashlib.sha256(raw).hexdigest(), 'base64': base64.b64encode(raw).decode(), 'uid': stat.st_uid, 'mode': oct(stat.st_mode & 0o777)}
    for path in Path('/proc').iterdir():
        if not path.name.isdecimal() or int(path.name) == os.getpid():
            continue
        try:
            stat = (path / 'stat').read_text().rsplit(')', 1)[1].split()
            status = (path / 'status').read_text().splitlines()
            uid = next(int(line.split()[1]) for line in status if line.startswith('Uid:'))
            if uid != 1200 or stat[0] == 'Z':
                continue
            arguments = [value.decode(errors='replace') for value in (path / 'cmdline').read_bytes().split(b'\x00') if value]
            data['processes'][path.name] = {'uid': uid, 'starttime': int(stat[19]), 'argv': arguments}
        except FileNotFoundError:
            continue
    return data

action = sys.argv[1]
assert action in ['snapshot', 'recover']
current = snapshot()
if action == 'snapshot':
    print(json.dumps(current))
    raise SystemExit(0)
before, allowed = json.loads(sys.argv[2]), set(json.loads(sys.argv[3]))
for name, expected in before['files'].items():
    assert current['files'].get(name) == expected, name
created = {name: row for name, row in current['files'].items() if name not in before['files']}
assert all(row['uid'] == 1200 and row['sha256'] in allowed for row in created.values()), created
for name, row in created.items():
    path = Path(name)
    assert path.is_file() and not path.is_symlink() and hashlib.sha256(path.read_bytes()).hexdigest() == row['sha256']
    path.unlink()
removed_directories = []
for name, row in sorted(current['directories'].items(), reverse=True):
    if row['exists'] and not before['directories'].get(name, {'exists': False})['exists']:
        path = Path(name)
        assert path.stat().st_uid == 1200 and not path.is_symlink() and not any(path.iterdir())
        path.rmdir()
        removed_directories.append(name)
after = snapshot()
assert after['files'] == before['files']
print(json.dumps({'removed_files': created, 'removed_directories': removed_directories, 'after': after}))
