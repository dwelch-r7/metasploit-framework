"""Native SDK job completion and narrowly scoped operator artifact cleanup."""
import base64
import json
import os
from pathlib import Path
import shlex
import subprocess
import sys
import time
import urllib.error
import urllib.request

from ray.job_submission import JobSubmissionClient, JobStatus


options = json.loads(sys.argv[1])
action = options['action']
client = JobSubmissionClient('http://127.0.0.1:' + os.environ['MODULE_TARGET_RAY_HEAD_PORT'])


def identifiers():
    return sorted(job.submission_id for job in client.list_jobs() if job.submission_id)


def terminal(identifier):
    deadline = time.monotonic() + 45
    delay = 0.05
    while True:
        status = client.get_job_status(identifier)
        if status in [JobStatus.SUCCEEDED, JobStatus.FAILED, JobStatus.STOPPED]:
            return status
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError('Job did not finish: ' + identifier)
        time.sleep(min(delay, remaining))
        delay = min(delay * 1.5, 0.5)


def details(identifier):
    status = terminal(identifier)
    return {'submission_id': identifier, 'status': str(status),
            'info': client.get_job_info(identifier).dict(), 'logs': client.get_job_logs(identifier)}


def temporary_files():
    return sorted(str(path) for path in Path('/tmp').iterdir())


if action == 'snapshot':
    result = {'submission_ids': identifiers(), 'temporary_paths': temporary_files(), 'uid': os.getuid(), 'gid': os.getgid()}
elif action == 'settle':
    baseline = options['baseline']
    current = identifiers()
    assert set(baseline).issubset(current), (baseline, current)
    added = sorted(set(current) - set(baseline))
    assert len(added) >= options.get('minimum', 0), added
    records = [details(identifier) for identifier in added]
    # Capture a terminal failure as evidence before refusing to delete/repair it.
    print('MODULE_TARGET_JOB_RECORDS:' + json.dumps(records, default=str), flush=True)
    assert all(record['status'] == 'SUCCEEDED' for record in records), records
    if options.get('remove', False):
        for identifier in added:
            assert client.delete_job(identifier) is True
        assert identifiers() == baseline
    result = {'records': records, 'baseline': baseline, 'after': identifiers(),
              'owned_submission_metadata_removed': options.get('remove', False)}
elif action == 'agent-control':
    baseline = identifiers()
    root = Path(options['root'])
    assert root.parent == Path('/tmp') and root.name.startswith('module-target-ray-jobs-')
    path = root / 'native-agent.txt'
    assert not path.exists()
    identifier = 'module-native-agent-' + options['nonce']
    code = ('import os,json; from pathlib import Path; '
            'Path(' + repr(str(path)) + ').write_text(' + repr(identifier) + '); '
            'print("RAY_AGENT_PROOF:"+json.dumps({"uid":os.getuid(),"pid":os.getpid(),"value":' + repr(identifier) + '}),flush=True)')
    entrypoint = ' '.join(shlex.quote(part) for part in [sys.executable, '-u', '-c', code])
    requests = []
    for route, command in [('/api/jobs/', 'ls'), ('/api/job_agent/jobs/', entrypoint)]:
        request = urllib.request.Request('http://127.0.0.1:' + os.environ['MODULE_TARGET_RAY_AGENT_PORT'] + route,
                                         data=json.dumps({'entrypoint': command}).encode(),
                                         headers={'Content-Type': 'application/json'})
        try:
            response = urllib.request.urlopen(request, timeout=15)
        except urllib.error.HTTPError as error:
            response = error
        with response:
            raw = response.read()
            requests.append({'route': route, 'entrypoint': command, 'status': response.status,
                             'body_base64': base64.b64encode(raw).decode()})
        if route == '/api/jobs/':
            assert requests[-1]['status'] == 404, requests[-1]
            assert identifiers() == baseline
        else:
            assert requests[-1]['status'] == 200, requests[-1]
            submitted = json.loads(raw)['submission_id']
    record = details(submitted)
    assert record['status'] == 'SUCCEEDED', record
    assert path.read_text() == identifier and path.stat().st_uid == 1000
    lines = [line.split(':', 1)[1] for line in record['logs'].splitlines() if line.startswith('RAY_AGENT_PROOF:')]
    assert len(lines) == 1
    facts = json.loads(lines[0])
    assert facts['uid'] == 1000 and facts['value'] == identifier
    assert client.delete_job(submitted) is True
    path.unlink()
    assert identifiers() == baseline
    result = {'requests': requests, 'record': record, 'facts': facts, 'restored': True}
elif action == 'cleanup-files':
    baseline = set(options['baseline'])
    added = sorted(set(temporary_files()) - baseline)
    records = []
    for value in added:
        path = Path(value)
        assert path.parent == Path('/tmp') and path.is_file() and not path.is_symlink(), value
        stat = path.stat()
        assert stat.st_uid == 1000, value
        records.append({'path': value, 'size': stat.st_size, 'uid': stat.st_uid, 'gid': stat.st_gid})
    # Only newly observed, regular, same-user top-level files are operator
    # cleanup candidates. Product directories, sockets and symlinks are refused.
    for record in records:
        Path(record['path']).unlink()
    assert temporary_files() == sorted(baseline)
    result = {'operator_removed_files': records, 'temporary_paths_restored': True}
elif action == 'launch':
    path = Path(options['path'])
    assert path.parent == Path('/tmp') and path.name.startswith('module-target-ray-calibration-')
    assert not path.exists()
    source = Path(options['source']).resolve(strict=True)
    assert source.parent == Path(os.environ['MODULE_TARGET_JOB_ARTIFACTS'])
    assert source.name.startswith('native-')
    raw = source.read_bytes()
    assert raw.startswith(b'\x7fELF')
    path.write_bytes(raw)
    path.chmod(0o700)
    log = path.with_suffix('.log')
    with log.open('ab', buffering=0) as output:
        process = subprocess.Popen([str(path)], stdin=subprocess.DEVNULL, stdout=output,
                                   stderr=subprocess.STDOUT, start_new_session=True)
    result = {'pid': process.pid, 'path': str(path), 'log': str(log), 'uid': path.stat().st_uid,
              'gid': path.stat().st_gid, 'bytes': len(raw)}
elif action == 'architecture-control':
    root = Path(options['root'])
    assert root.parent == Path('/tmp') and root.name.startswith('module-target-ray-jobs-')
    marker = root / ('native-arch-' + options['architecture'])
    assert marker.parent == root and not marker.exists()
    source = Path(options['source']).resolve(strict=True)
    assert source.parent == Path(os.environ['MODULE_TARGET_JOB_ARTIFACTS'])
    assert source.name.startswith('native-arch-')
    raw = source.read_bytes()
    assert raw.startswith(b'\x7fELF')
    executable = root / ('native-arch-' + options['architecture'] + '.elf')
    assert not executable.exists()
    executable.write_bytes(raw)
    executable.chmod(0o700)
    result = {'architecture': options['architecture'], 'uid': os.getuid(), 'gid': os.getgid(),
              'elf_machine': int.from_bytes(raw[18:20], 'little'), 'uname': list(os.uname())}
    try:
        process = subprocess.run([str(executable)], capture_output=True, timeout=10)
        result.update(status='executed', exitstatus=process.returncode,
                      stdout_base64=base64.b64encode(process.stdout).decode(),
                      stderr_base64=base64.b64encode(process.stderr).decode())
        assert process.returncode == 0, result
        assert marker.read_text() == options['value'] and marker.stat().st_uid == 1000
        result['exact_marker'] = True
        marker.unlink()
    except OSError as error:
        if error.errno != 8:
            raise
        result.update(status='unsupported_executable_format', errno=error.errno, error=str(error))
    finally:
        executable.unlink()
elif action == 'cleanup-root':
    root = Path(options['root'])
    assert root.parent == Path('/tmp') and root.name.startswith('module-target-ray-jobs-')
    files = list(root.iterdir())
    assert all(path.is_file() and not path.is_symlink() and path.stat().st_uid == 1000 for path in files)
    result = {'operator_removed_root_files': [str(path) for path in files]}
    for path in files:
        path.unlink()
    root.rmdir()
    result['root_absent'] = not root.exists()
else:
    raise ValueError('Unknown native job observer action')

print('MODULE_TARGET_JOBS_JSON:' + json.dumps(result, default=str))
