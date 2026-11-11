"""Installed Ray identity and native workload controls inside the owned target."""
import base64
import hashlib
import json
import os
from pathlib import Path
import shlex
import sys
import time

import psutil
import ray

options = json.loads(sys.argv[1])
action = options['action']
FIXTURE_NAMES = {'utf8': "outside 'quoted' file.txt", 'reserved': 'reserved #?%2f café.txt',
                 'empty': 'empty.txt', 'missing': 'missing.txt'}


def poll(predicate, seconds=60):
    deadline = time.monotonic() + seconds
    delay = 0.05
    while True:
        result = predicate()
        if result:
            return result
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError('Native Ray condition did not complete')
        time.sleep(min(delay, remaining))
        delay = min(delay * 1.5, 0.5)


def processes():
    rows = []
    for process in psutil.process_iter(['pid', 'ppid', 'uids', 'cmdline', 'status', 'memory_info']):
        try:
            data = process.info
            arguments = data['cmdline'] or []
            role = Path(arguments[0]).name if arguments and Path(arguments[0]).name in ['gcs_server', 'raylet'] else None
            for candidate in ['dashboard/agent.py', 'dashboard/dashboard.py', 'autoscaler/_private/monitor.py']:
                if any(argument.endswith('/' + candidate) for argument in arguments):
                    role = candidate
            if role:
                rows.append({'role': role, 'pid': data['pid'], 'ppid': data['ppid'], 'uid': data['uids'].real,
                             'cmdline': arguments, 'status': data['status'], 'rss': data['memory_info'].rss})
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return rows


if action == 'identity':
    root = Path(ray.__file__).parent
    sources = {}
    for name in options['files']:
        relative = Path(name)
        assert not relative.is_absolute() and '..' not in relative.parts
        path = root / relative
        data = path.read_bytes()
        sources[name] = {'sha256': hashlib.sha256(data).hexdigest(), 'bytes_base64': base64.b64encode(data).decode()}
    static_root = root / 'dashboard/client/build/static'
    static_files = [path for path in static_root.rglob('*') if path.is_file() and not path.is_symlink()]
    # The smallest real bundled asset keeps the ordinary static-serving control
    # short without inventing a route or patching the application.
    asset = min(static_files, key=lambda path: (path.stat().st_size, str(path)))
    asset_bytes = asset.read_bytes()
    result = {'version': ray.__version__, 'commit': ray.__commit__, 'python': sys.version,
              'uid': os.getuid(), 'gid': os.getgid(), 'sources': sources, 'processes': processes(),
              'static_asset': {'path': '/static/' + str(asset.relative_to(static_root)),
                               'sha256': hashlib.sha256(asset_bytes).hexdigest(), 'size': len(asset_bytes)},
              'static_build_exists': (root / 'dashboard/client/build/static/js').is_dir()}
elif action == 'core':
    ray.init(address='auto', namespace='module-target-native-' + options['nonce'], logging_level='ERROR')
    try:
        nodes = [node for node in ray.nodes() if node['Alive']]
        assert len(nodes) == 1, nodes

        @ray.remote
        def native_task():
            import os
            return {'pid': os.getpid(), 'uid': os.getuid(), 'value': 41 + 1}

        value = ray.get(native_task.remote(), timeout=45)
        assert value['uid'] == 1000 and value['value'] == 42
        result = {'nodes': nodes, 'task': value, 'processes': processes(),
                  'driver_job_id': ray.get_runtime_context().get_job_id(),
                  'history_scope': 'A real native driver/task can leave Ray driver history; not claimed erased'}
    finally:
        ray.shutdown()
elif action == 'seed':
    root = Path('/tmp/module-target-ray-' + options['nonce'])
    assert not root.exists()
    root.mkdir()
    content = "Ray exact + $HOME; 'quoted' café\n".encode()
    paths = {name: root / filename for name, filename in FIXTURE_NAMES.items()}
    for name in ['utf8', 'reserved']:
        paths[name].write_bytes(content)
    paths['empty'].write_bytes(b'')
    logs = Path('/tmp/ray/session_latest/logs').resolve()
    log = logs / ('module-target-' + options['nonce'] + '.log')
    assert not log.exists()
    log.write_bytes(content)
    result = {'root': str(root), 'paths': {key: str(value) for key, value in paths.items()},
              'log': str(log), 'log_directory': str(logs), 'content_base64': base64.b64encode(content).decode(),
              'uid': root.stat().st_uid}
elif action == 'jobs':
    from ray.job_submission import JobSubmissionClient, JobStatus

    client = JobSubmissionClient('http://127.0.0.1:' + os.environ['MODULE_TARGET_RAY_HEAD_PORT'])
    root = Path(options['root'])
    assert root.is_dir() and root.name == 'module-target-ray-' + options['nonce']
    records = []
    baseline = [job.submission_id for job in client.list_jobs() if job.submission_id]
    for iteration in range(2):
        identifier = 'module-native-' + options['nonce'] + '-' + str(iteration)
        path = root / ('job-' + str(iteration) + '.txt')
        code = ('import os,json; from pathlib import Path; '
                'Path(' + repr(str(path)) + ').write_text(' + repr('Ray job exact ' + identifier) + '); '
                'print("MODULE_TARGET_JOB_JSON:"+json.dumps({"pid":os.getpid(),"uid":os.getuid(),"id":' + repr(identifier) + '}),flush=True)')
        entrypoint = ' '.join(shlex.quote(part) for part in [sys.executable, '-u', '-c', code])
        submitted = client.submit_job(entrypoint=entrypoint, submission_id=identifier)
        assert submitted == identifier
        record = {'submission_id': identifier, 'entrypoint': entrypoint}
        records.append(record)

        def terminal():
            status = client.get_job_status(identifier)
            return status if status in [JobStatus.SUCCEEDED, JobStatus.FAILED, JobStatus.STOPPED] else None

        status = poll(terminal, 90)
        record['status'] = str(status)
        record['info'] = client.get_job_info(identifier).dict()
        record['logs'] = client.get_job_logs(identifier)
        assert status == JobStatus.SUCCEEDED, record
        lines = [line.split(':', 1)[1] for line in record['logs'].splitlines() if line.startswith('MODULE_TARGET_JOB_JSON:')]
        assert len(lines) == 1, record
        facts = json.loads(lines[0])
        assert facts['id'] == identifier and facts['uid'] == 1000
        assert path.read_text() == 'Ray job exact ' + identifier
        record['facts'] = facts
        poll(lambda: not psutil.pid_exists(facts['pid']), 10)
        assert client.delete_job(identifier) is True
        path.unlink()
        record['deleted'] = True
    remaining = [job.submission_id for job in client.list_jobs() if job.submission_id]
    assert sorted(remaining) == sorted(baseline), remaining
    result = {'records': records, 'baseline_submission_ids': baseline, 'after_submission_ids': remaining,
              'owned_submission_metadata_and_files_removed': True,
              'history_scope': 'Native Ray driver history and product log files can persist; capture them separately'}
elif action == 'verify-fixtures':
    root = Path(options['root'])
    assert root == Path('/tmp/module-target-ray-' + options['nonce'])
    content = base64.b64decode(options['content_base64'])
    for name in ['utf8', 'reserved']:
        assert Path(options['paths'][name]).read_bytes() == content
    assert Path(options['paths']['empty']).read_bytes() == b''
    assert not Path(options['paths']['missing']).exists()
    assert Path(options['log']).read_bytes() == content
    result = {'fixture_bytes_unchanged': True}
elif action == 'cleanup':
    root = Path(options['root'])
    assert root == Path('/tmp/module-target-ray-' + options['nonce'])
    # These are precisely the three fixture files and one fixture directory we
    # created. No recursive removal or repair of product state.
    for name in ['utf8', 'reserved', 'empty']:
        (root / FIXTURE_NAMES[name]).unlink()
    root.rmdir()
    log = Path(options['log'])
    assert log.name == 'module-target-' + options['nonce'] + '.log' and str(log).startswith('/tmp/ray/')
    log.unlink()
    result = {'owned_fixture_paths_absent': not root.exists() and not log.exists()}
else:
    raise ValueError('Unknown native action')
print('MODULE_TARGET_RAY_JSON:' + json.dumps(result, default=str))
