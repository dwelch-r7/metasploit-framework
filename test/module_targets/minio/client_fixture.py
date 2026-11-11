"""Host-only genuine mc fixture driver; target nodes need no Python or packages."""
import base64
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys

from native import Native


def state(client, path):
    client.command('node1', 'test', '!', '-L', path)
    _, code = client.command('node1', 'test', '-f', path, expected=None)
    assert code in (0, 1)
    if code == 1:
        client.command('node1', 'test', '!', '-e', path)
        return dict(exists=False)
    raw, _ = client.command('node1', 'cat', path)
    stat, _ = client.command('node1', 'stat', '-c', '%u:%g:%a:%F', path)
    return dict(exists=True, bytes_base64=base64.b64encode(raw).decode(),
                sha256=hashlib.sha256(raw).hexdigest(), stat=stat.decode().strip())


def write(client, path, raw):
    client.command('node1', 'sh', '-c', 'umask 077; cat > "$1"', 'sh', path, stdin=raw)


def make_config(client, directory, suffix):
    def mc(*args, stdin=None):
        return client.command('node1', '/usr/local/bin/mc', '--config-dir', directory,
                              '--json', *args, stdin=stdin)
    mc('alias', 'list')
    path = directory + '/config.json'
    raw, _ = client.command('node1', 'cat', path)
    for name in json.loads(raw)['aliases']:
        mc('alias', 'rm', name)
    seeds = {}
    for index, service in enumerate(('node1', 'node2')):
        name = 'owned' + suffix + str(index)
        seed = dict(url=f'http://{service}:9000', accessKey=f'module-{suffix}-access-{index}',
                    secretKey=f'module-{suffix}-secret-{index}-proof',
                    api='S3v4' if index == 0 else 'S3v2', path='auto' if index == 0 else 'on')
        seeds[name] = seed
        mc('alias', 'import', name, stdin=json.dumps(seed).encode())
    raw, _ = client.command('node1', 'cat', path)
    aliases = json.loads(raw)['aliases']
    assert aliases == seeds, dict(actual=aliases, seeds=seeds)
    return dict(path=path, aliases=aliases, valid_state=state(client, path), seeds=seeds)


def main(runtime_path, token, action, case):
    assert re.fullmatch(r'minio_[a-z0-9_]+', token), token
    assert case in ('default_home', 'custom_path', 'missing', 'empty', 'malformed',
                    'aliases_empty', 'default_after_custom'), case
    runtime = json.loads(Path(runtime_path).read_text())
    directory = Path(runtime['artifacts']) / ('fixture-' + token)
    directory.mkdir(exist_ok=True)
    runtime['artifacts'] = str(directory)
    client = Native(runtime)
    record_path = directory / 'state.json'
    if action == 'prepare':
        assert not record_path.exists(), record_path
        record = dict(token=token, case=case, claimed=[], configs={})
        record_path.write_text(json.dumps(record, indent=2) + '\n')
        for label, target in (('home', '/home/minio/.mc'),
                              ('custom', '/home/minio/minio module ' + token)):
            client.command('node1', 'sh', '-c', 'test ! -e "$1" && test ! -L "$1"', 'sh', target)
            record['claimed'].append(target)
            record_path.write_text(json.dumps(record, indent=2) + '\n')
            record['configs'][label] = make_config(client, target, label)
            record_path.write_text(json.dumps(record, indent=2) + '\n')
        path = record['configs']['home']['path']
        if case == 'missing':
            client.command('node1', 'rm', '--', path)
        elif case == 'empty':
            write(client, path, b'')
        elif case == 'malformed':
            write(client, path, b'{"aliases":\n')
        elif case == 'aliases_empty':
            for name in record['configs']['home']['aliases']:
                client.command('node1', '/usr/local/bin/mc', '--config-dir', '/home/minio/.mc',
                               '--json', 'alias', 'rm', name)
        record['before'] = {label: state(client, data['path']) for label, data in record['configs'].items()}
        record_path.write_text(json.dumps(record, indent=2) + '\n')
    else:
        record = json.loads(record_path.read_text())
        assert record['token'] == token and record['case'] == case
        if action == 'verify':
            actual = {label: state(client, data['path']) for label, data in record['configs'].items()}
            assert actual == record['before'], dict(before=record['before'], after=actual)
            record['owner_input_unchanged'] = True
        elif action == 'restore':
            errors = []
            # Restore and verify valid bytes before removing only fresh-owned dirs.
            for label, data in record['configs'].items():
                try:
                    saved = data['valid_state']
                    write(client, data['path'], base64.b64decode(saved['bytes_base64'], validate=True))
                    mode = saved['stat'].split(':')[2]
                    client.command('node1', 'chmod', mode, data['path'])
                    assert state(client, data['path']) == saved
                except (AssertionError, OSError, ValueError, subprocess.SubprocessError) as error:
                    errors.append(dict(operation='restore-' + label, error=str(error)))
            for target in record['claimed']:
                assert target in ('/home/minio/.mc', '/home/minio/minio module ' + token)
                try:
                    client.command('node1', 'rm', '-rf', '--', target)
                    client.command('node1', 'sh', '-c', 'test ! -e "$1" && test ! -L "$1"', 'sh', target)
                except (AssertionError, OSError, ValueError, subprocess.SubprocessError) as error:
                    errors.append(dict(operation='remove-owned-' + target, error=str(error)))
            record['restoration_errors'] = errors
            record['initial_absence_restored'] = not errors
            record_path.write_text(json.dumps(record, indent=2) + '\n')
            assert not errors, errors
        else:
            raise ValueError(action)
        record_path.write_text(json.dumps(record, indent=2) + '\n')
    print(json.dumps(record))


if __name__ == '__main__':
    main(*sys.argv[1:])
