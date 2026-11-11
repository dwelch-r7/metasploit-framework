"""Bind genuine session use to atomic pre-exec identity, never inherited env."""
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time

from native import Native


def parse_stat(raw):
    # proc_pid_stat(5): comm is parenthesized and can itself contain spaces/').
    text = raw.decode().strip()
    prefix, separator, tail = text.rpartition(') ')
    fields = tail.split()
    assert separator and len(fields) >= 20, text
    pid = int(prefix.split(' (', 1)[0])
    return dict(pid=pid, state=fields[0], ppid=int(fields[1]), starttime=int(fields[19]), raw_stat=text)


def parse_identity(raw):
    lines = raw.decode().splitlines()
    assert len(lines) >= 3 and lines[0].startswith('STAT ') and lines[1].startswith('EXE '), lines
    result = parse_stat(lines[0][5:].encode())
    result['exe'] = lines[1][4:]
    status = '\n'.join(lines[2:])
    uid = re.search(r'^Uid:\s+([0-9]+\s+[0-9]+\s+[0-9]+\s+[0-9]+)$', status, re.M)
    gid = re.search(r'^Gid:\s+([0-9]+\s+[0-9]+\s+[0-9]+\s+[0-9]+)$', status, re.M)
    pid = re.search(r'^Pid:\s+([0-9]+)$', status, re.M)
    assert uid and gid and pid
    result['uid'] = [int(value) for value in uid[1].split()]
    result['gid'] = [int(value) for value in gid[1].split()]
    assert int(pid[1]) == result['pid']
    result['raw_status'] = status
    assert result['starttime'] > 0
    return result


def validate_owned(record, actual, final=True):
    before = record['pre_exec']
    assert actual['pid'] > 1 and actual['pid'] == before['pid'], actual
    assert actual['starttime'] == before['starttime'], dict(before=before, actual=actual)
    assert actual['uid'] == before['uid'] == [record['uid']] * 4, actual
    assert actual['gid'] == before['gid'] == [record['gid']] * 4, actual
    assert actual['state'] in ('R', 'S', 'D', 'I'), actual
    expected = record['shell_exe'] if record['kind'] == 'shell' else dict(path=record['payload'], sha256=record['sha256'])
    allowed = [expected] if final else [record['shell_exe'], dict(path=record['payload'], sha256=record['sha256'])]
    assert any(actual['exe'] == item['path'] and actual['exe_sha256'] == item['sha256'] for item in allowed), actual
    if final and record['kind'] == 'shell':
        assert base64.b64decode(actual['cmdline_base64'], validate=True).split(b'\0') == [b'/bin/sh', b''], actual


def process_state(client, pid):
    values = []
    for command in (['cat', f'/proc/{pid}/stat'], ['cat', f'/proc/{pid}/status'],
                    ['readlink', f'/proc/{pid}/exe'], ['sha256sum', f'/proc/{pid}/exe'],
                    ['cat', f'/proc/{pid}/cmdline']):
        raw, code = client.command('node1', *command, expected=None)
        if code:
            _, absent = client.command('node1', 'test', '!', '-d', f'/proc/{pid}', expected=None)
            if absent == 0:
                return None
            raise AssertionError(dict(operation=command, exit=code))
        values.append(raw)
    actual = parse_identity(b'STAT ' + values[0].rstrip(b'\n') + b'\nEXE ' + values[2].rstrip(b'\n') + b'\n' + values[1])
    digest = values[3].decode().split()
    assert digest and re.fullmatch(r'[0-9a-f]{64}', digest[0])
    actual.update(exe_sha256=digest[0], cmdline_base64=base64.b64encode(values[4]).decode())
    return actual


def load_pre_exec(client, record):
    raw, _ = client.command('node1', 'cat', record['identity'])
    stat, _ = client.command('node1', 'stat', '-c', '%u:%g:%a', record['identity'])
    assert stat.decode().strip() == f"{record['uid']}:{record['gid']}:600"
    before = parse_identity(raw)
    assert before['pid'] > 1 and str(before['pid']) not in record['before_pids']
    assert before['uid'] == [record['uid']] * 4 and before['gid'] == [record['gid']] * 4
    assert before['exe'] == record['shell_exe']['path']
    record.update(pre_exec=before, pid=before['pid'], atomic_identity_base64=base64.b64encode(raw).decode())


def compose_command(client, runtime, *arguments):
    argv = runtime['compose'] + list(arguments)
    client.journal('native-command-attempts.jsonl', dict(argv=argv))
    result = subprocess.run(argv, capture_output=True, timeout=25,
                            env={**os.environ, **runtime['compose_environment']})
    client.journal('native-commands.jsonl', dict(argv=argv, exitstatus=result.returncode,
                                                stdout=result.stdout.decode(), stderr=result.stderr.decode()))
    assert result.returncode == 0
    return result.stdout


def main(runtime_path, token, action, kind, session_pid=None, session_peer=None, proof_base64=None):
    assert re.fullmatch(r'minio_[a-z0-9_]+', token) and kind in ('shell', 'meterpreter')
    runtime = json.loads(Path(runtime_path).read_text())
    artifacts = Path(runtime['artifacts'])
    directory = artifacts / ('session-' + token)
    directory.mkdir(exist_ok=True)
    runtime['artifacts'] = str(directory)
    client = Native(runtime)
    record_path = directory / 'session.json'
    payload = '/tmp/module-target-' + token + '.elf'
    identity = '/tmp/module-target-' + token + '.identity'
    proof = '/tmp/module-target-' + token + '.proof'
    if action == 'launch':
        assert not record_path.exists()
        source = artifacts / (token + '-' + kind + '.elf')
        raw = source.read_bytes()
        assert raw.startswith(b'\x7fELF') and raw[18:20] == b'\x3e\x00'
        owned_paths = [payload, identity, identity + '.tmp', proof]
        for target in owned_paths:
            client.command('node1', 'sh', '-c', 'test ! -e "$1" && test ! -L "$1"', 'sh', target)
        shell_path, _ = client.command('node1', 'readlink', '-f', '/bin/sh')
        shell_sha, _ = client.command('node1', 'sha256sum', '/bin/sh')
        pids, _ = client.command('node1', 'sh', '-c', 'printf "%s\\n" /proc/[0-9]*')
        nodes = json.loads((artifacts / 'runtime-identities.out').read_text())
        node = next(row for row in nodes if row['Config']['Labels']['com.docker.compose.service'] == 'node1')
        networks = list(node['NetworkSettings']['Networks'].values())
        assert len(networks) == 1
        record = dict(token=token, kind=kind, payload=payload, identity=identity, proof=proof,
                      source=str(source), sha256=hashlib.sha256(raw).hexdigest(), owned_paths=owned_paths,
                      uid=client.assets['assembly']['uid'], gid=client.assets['assembly']['gid'],
                      before_pids=[Path(value).name for value in pids.decode().split()],
                      shell_exe=dict(path=shell_path.decode().strip(), sha256=shell_sha.decode().split()[0]),
                      container_id=node['Id'], node1_host=networks[0]['IPAddress'])
        record_path.write_text(json.dumps(record, indent=2) + '\n')
        assert compose_command(client, runtime, 'ps', '--quiet', 'node1').decode().strip() == record['container_id']
        client.command('node1', 'sh', '-c', 'umask 077; cat > "$1"; chmod 700 "$1"', 'sh', payload, stdin=raw)
        actual_sha, _ = client.command('node1', 'sha256sum', payload)
        actual_stat, _ = client.command('node1', 'stat', '-c', '%u:%g:%a:%s', payload)
        record['target_elf_before_launch'] = dict(sha256=actual_sha.decode().split()[0], stat=actual_stat.decode().strip())
        record_path.write_text(json.dumps(record, indent=2) + '\n')
        assert record['target_elf_before_launch'] == dict(sha256=record['sha256'], stat=f"{record['uid']}:{record['gid']}:700:{len(raw)}")
        # Publish all pre-exec fields in one atomic rename, before exec changes env.
        script = 'set -eu; umask 077; { printf "STAT "; cat /proc/$$/stat; printf "EXE "; readlink /proc/$$/exe; cat /proc/$$/status; } > "$1.tmp"; mv -- "$1.tmp" "$1"; exec "$2"'
        record['launch_attempted'] = True
        record_path.write_text(json.dumps(record, indent=2) + '\n')
        compose_command(client, runtime, 'exec', '--detach', '-T', 'node1', '/bin/sh', '-c', script, 'sh', identity, payload)
        deadline = time.monotonic() + 5
        while True:
            _, code = client.command('node1', 'test', '-f', identity, expected=None)
            if code == 0:
                break
            assert code == 1 and time.monotonic() < deadline
            time.sleep(0.1)
        load_pre_exec(client, record)
    else:
        if not record_path.exists() and action == 'cleanup':
            print(json.dumps(dict(no_owned_launch=True)))
            return
        record = json.loads(record_path.read_text())
        assert record['token'] == token and record['kind'] == kind
        if action == 'verify':
            assert compose_command(client, runtime, 'ps', '--quiet', 'node1').decode().strip() == record['container_id']
            assert int(session_pid) == record['pid'] and session_peer == record['node1_host']
            actual = process_state(client, record['pid'])
            assert actual is not None
            validate_owned(record, actual)
            ancestry = [actual]
            parent = actual['ppid']
            while parent > 1 and str(parent) not in record['before_pids']:
                assert len(ancestry) < 32 and parent not in [row['pid'] for row in ancestry]
                row = process_state(client, parent)
                assert row is not None
                ancestry.append(row)
                parent = row['ppid']
            value, _ = client.command('node1', 'cat', proof)
            owner, _ = client.command('node1', 'stat', '-c', '%u:%g', proof)
            assert value == base64.b64decode(proof_base64, validate=True) and owner.decode().strip() == f"{record['uid']}:{record['gid']}"
            record['genuine_session'] = dict(pid=int(session_pid), peer=session_peer, ancestry=ancestry,
                                            proof_sha256=hashlib.sha256(value).hexdigest(), proof_bytes=len(value))
        elif action == 'cleanup':
            errors = []
            namespace_owned = False
            try:
                assert compose_command(client, runtime, 'ps', '--quiet', 'node1').decode().strip() == record['container_id']
                namespace_owned = True
                if record.get('launch_attempted') and 'pre_exec' not in record:
                    load_pre_exec(client, record)
                if 'pre_exec' in record:
                    actual = process_state(client, record['pid'])
                    if actual is not None:
                        validate_owned(record, actual, final=False)
                        record['identity_before_signal'] = actual
                        record_path.write_text(json.dumps(record, indent=2) + '\n')
                        client.command('node1', 'sh', '-c', 'kill -TERM "$1"', 'sh', str(record['pid']))
                        deadline = time.monotonic() + 5
                        while process_state(client, record['pid']) is not None:
                            assert time.monotonic() < deadline
                            time.sleep(0.1)
            except (AssertionError, OSError, ValueError, subprocess.SubprocessError) as error:
                errors.append(dict(operation='owned-process', error=str(error)))
            for target in record['owned_paths'] if namespace_owned else []:
                try:
                    client.command('node1', 'rm', '-f', '--', target)
                    client.command('node1', 'sh', '-c', 'test ! -e "$1" && test ! -L "$1"', 'sh', target)
                except (AssertionError, OSError, ValueError, subprocess.SubprocessError) as error:
                    errors.append(dict(operation='owned-file-' + target, error=str(error)))
            record.update(cleanup_errors=errors, owned_process_and_files_absent=not errors)
            record_path.write_text(json.dumps(record, indent=2) + '\n')
            assert not errors, errors
        else:
            raise ValueError(action)
    record_path.write_text(json.dumps(record, indent=2) + '\n')
    print(json.dumps(record))


if __name__ == '__main__':
    main(*sys.argv[1:])
