"""Read-only Salt job evidence, shared by native and owning-module controls.

The benign native calibration may hold its own code at a gate. The detached
owning-call observer never changes a publication, payload, vendor method or job.
Proc disappearance is Salt _return_pub behavior, not FileDropper validation.
"""
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import resource
import shutil
import signal
import subprocess
import sys
import time
import uuid

import salt.config
import salt.payload
import salt.utils.jid

ROOT = Path('/var/run/salt/job-observers')
MAX_BYTES = 128 * 1024
MAX_REPORT_BYTES = 512 * 1024
MAX_CONTROL_BYTES = 64 * 1024
MAX_DIRECTORY_BYTES = 2 * 1024 * 1024
MAX_JOBS = 8
MAX_PROCESS_RECORDS = 256
POLL_SECONDS = 0.02
LINEAGE_SECONDS = 0.02


def encode(value):
    if isinstance(value, bytes):
        return {'bytes_base64': base64.b64encode(value).decode()}
    raise TypeError(type(value).__name__)


def read_bytes(path, limit=MAX_BYTES):
    with path.open('rb') as stream:
        raw = stream.read(limit + 1)
    if len(raw) > limit:
        raise ValueError('Job evidence exceeds its bounded file budget: ' + str(path))
    return raw


def process(pid):
    try:
        fields = (Path('/proc') / str(pid) / 'stat').read_text().split(') ', 1)[1].split()
        return {'pid': int(pid), 'exists': True, 'state': fields[0], 'ppid': int(fields[1]),
                'starttime': fields[19], 'wait_status': int(fields[49])}
    except (FileNotFoundError, ProcessLookupError):
        return {'pid': int(pid), 'exists': False}


def running(value):
    return value['exists'] and value['state'] not in ['Z', 'X']


def same_running(identity):
    current = process(identity['pid'])
    return running(current) and current['starttime'] == identity['starttime']


def cached_returns(jid, options, serial):
    # Match native local_cache.get_jid's envelope/legacy-format handling, with
    # bounded file reads instead of its unbounded retry on corrupt MessagePack.
    # https://github.com/saltstack/salt/blob/v3000.1/salt/returners/local_cache.py
    directory = Path(salt.utils.jid.jid_dir(jid, str(Path(options['cachedir']) / 'jobs'), options['hash_type']))
    results = {}
    for path in directory.glob('*/return.p'):
        if len(results) >= 16:
            raise ValueError('Native cache contains too many node return envelopes')
        value = serial.loads(read_bytes(path))
        if not isinstance(value, dict) or 'return' not in value:
            value = {'return': value}
        output = path.parent / 'out.p'
        if output.exists():
            value['out'] = serial.loads(read_bytes(output))
        results[path.parent.name] = value
    return results


def transient_cache_read(operation, seconds=2):
    """Retry a real incomplete cache write within one bounded read interval."""
    deadline = time.monotonic() + seconds
    while True:
        try:
            return operation()
        except (FileNotFoundError, ValueError, EOFError):
            if time.monotonic() >= deadline:
                raise TimeoutError('Native cache files remained incomplete for two seconds')
            time.sleep(POLL_SECONDS)


def transient_cached_returns(jid, options, serial):
    return transient_cache_read(lambda: cached_returns(jid, options, serial))


def wait_for(operation, seconds=30):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        result = operation()
        if result:
            return result
        time.sleep(POLL_SECONDS)
    raise TimeoutError('Salt job observation did not complete within its bound')


def write_json(path, value):
    raw = json.dumps(value, default=encode, sort_keys=True)
    size = len(raw.encode())
    limit = MAX_REPORT_BYTES if path.name == 'finished.json' else MAX_CONTROL_BYTES
    if size > limit:
        raise ValueError('Salt observation JSON exceeds its bounded file budget')
    directory = next((parent for parent in path.parents if parent.parent == ROOT), None)
    if directory:
        total = sum(item.stat().st_size for item in directory.rglob('*') if item.is_file())
        if total + size > MAX_DIRECTORY_BYTES:
            raise ValueError('Salt observer directory exceeds its two-MiB budget')
    temporary = path.with_suffix('.writing')
    temporary.write_text(raw)
    os.replace(str(temporary), str(path))


class JobObservation:
    """Observe actual configured proc files, returner cache and worker identities."""

    def __init__(self, selector, function):
        self.selector = selector
        self.function = function
        self.state = json.loads(Path('/var/run/salt/module-target.json').read_text())
        self.master_options = salt.config.master_config('/etc/salt/master')
        if self.master_options['master_job_cache'] != 'local_cache':
            raise ValueError('The bounded cache reader requires the genuine local_cache returner')
        self.serial = salt.payload.Serial(self.master_options)
        self.options = {}
        self.baseline = {}
        self.logs = {}
        self.jobs = {}
        self.partial_reads = {}
        self.lineage = {}
        self.proofs = []
        self.lineage_sampled_at = 0
        for role in ['minion-a', 'minion-b']:
            opts = salt.config.minion_config(self.state['roles'][role]['config'])
            if opts['multiprocessing'] is not True:
                raise ValueError('This job control requires genuine multiprocessing workers')
            self.options[role] = opts
            directory = Path(opts['cachedir']) / 'proc'
            self.baseline[role] = {path.name for path in directory.glob('*')}
            if len(self.baseline[role]) > 32:
                raise ValueError('Too many pre-existing proc files for a fresh owning call')
            log = Path(opts['log_file'])
            info = log.stat() if log.exists() else None
            self.logs[role] = {'path': str(log), 'offset': info.st_size if info else 0,
                               'inode': info.st_ino if info else None}
        self.expected = sorted(role for role, opts in self.options.items()
                               if re.match(selector, opts['id']))

    def sample(self):
        for role, opts in self.options.items():
            for path in (Path(opts['cachedir']) / 'proc').glob('*'):
                if path.name in self.baseline[role] or role in self.jobs.get(path.name, {}):
                    continue
                try:
                    raw = read_bytes(path)
                    load = self.serial.loads(raw)
                except (FileNotFoundError, ValueError, EOFError) as error:
                    # Salt can be writing the real proc record during this read.
                    self.partial_reads[role + ':' + path.name] = type(error).__name__
                    if len(self.partial_reads) > 32:
                        raise ValueError('Too many incomplete proc observations')
                    continue
                if not isinstance(load, dict) or load.get('fun') != self.function:
                    continue
                if load.get('tgt') != self.selector or load.get('tgt_type') != 'pcre':
                    continue
                if load.get('jid') != path.name:
                    raise ValueError('Actual proc filename does not match its decoded JID')
                if len(self.jobs) >= MAX_JOBS and path.name not in self.jobs:
                    raise ValueError('Too many publications for one bounded observation')
                worker = process(load['pid'])
                self.jobs.setdefault(path.name, {})[role] = {
                    'proc_path': str(path), 'proc_base64': base64.b64encode(raw).decode(),
                    'load': load, 'worker_live': worker, 'observed_live': running(worker),
                    'default_proc_path_exists': (Path('/var/cache/salt/minion/proc') / path.name).exists()
                }
        for jobs in self.jobs.values():
            for entry in jobs.values():
                entry['proc_absent'] = not Path(entry['proc_path']).exists()
                entry['worker_last'] = process(entry['worker_live']['pid'])
        self.sample_lineage()

    def sample_lineage(self):
        """Retain witnessed edges while an unproved job lineage is still live.

        Scanning is throttled to at most 50Hz and stops once its live frontier
        ends or its session proof is captured. Fast daemonization can still be
        missed; that is an explicit setup failure, never inferred ancestry.
        """
        now = time.monotonic()
        if now - self.lineage_sampled_at < LINEAGE_SECONDS:
            return
        proved = {(item['jid'], item['role']) for item in self.proofs}
        needed = {(jid, role) for jid, jobs in self.jobs.items() for role in jobs if (jid, role) not in proved}
        frontier = [entry['worker_live'] for jid, jobs in self.jobs.items()
                    for role, entry in jobs.items() if (jid, role) in needed and entry['observed_live']]
        frontier.extend(value for value in self.lineage.values() if (value['jid'], value['role']) in needed)
        if not needed or not any(same_running(value) for value in frontier):
            return
        self.lineage_sampled_at = now
        snapshot = {}
        for path in Path('/proc').iterdir():
            if path.name.isdigit():
                value = process(int(path.name))
                if value['exists']:
                    snapshot[value['pid']] = value
        for jid, jobs in self.jobs.items():
            for role, entry in jobs.items():
                worker = entry['worker_live']
                if entry['observed_live']:
                    key = str(worker['pid']) + ':' + worker['starttime']
                    self.lineage.setdefault(key, dict(worker, role=role, jid=jid, parent_identity=None))
        for unused in range(8):
            added = False
            for value in snapshot.values():
                key = str(value['pid']) + ':' + value['starttime']
                parent = snapshot.get(value['ppid'])
                if key in self.lineage or not parent:
                    continue
                if int(parent['starttime']) > int(value['starttime']):
                    # A reused numeric parent PID is not a witnessed parent edge.
                    continue
                parent_key = str(parent['pid']) + ':' + parent['starttime']
                if parent_key in self.lineage:
                    if len(self.lineage) >= MAX_PROCESS_RECORDS:
                        raise ValueError('Salt job process lineage exceeded its 256-record bound')
                    origin = self.lineage[parent_key]
                    self.lineage[key] = dict(value, role=origin['role'], jid=origin['jid'], parent_identity=parent_key)
                    added = True
            if not added:
                break

    def proof(self, jid, role, pids, token):
        self.sample()
        if token != self.state['roles'][role]['token'] or not 1 <= len(pids) <= 4:
            raise ValueError('Session role/token or process list does not match the genuine cluster')
        job = self.jobs[jid][role]
        worker = job['worker_live']
        root = str(worker['pid']) + ':' + worker['starttime']
        chains = []
        for pid in pids:
            current = process(pid)
            if not running(current):
                raise ValueError('Session process was not live before callback close')
            environment = dict(item.split(b'=', 1) for item in read_bytes(Path('/proc') / str(pid) / 'environ').split(b'\0') if b'=' in item)
            if environment.get(b'MSF_MODULE_TARGET_TOKEN', b'').decode() != token or environment.get(b'MSF_MODULE_TARGET_ROLE', b'').decode() != role:
                raise ValueError('Session PID environment does not match its actual role/token')
            key = str(pid) + ':' + current['starttime']
            chain = []
            while key in self.lineage and len(chain) < 16:
                value = self.lineage[key]
                chain.append(value)
                if key == root:
                    break
                key = value['parent_identity']
            if not chain or key != root:
                raise ValueError('Observer missed actual session-to-Salt-worker ancestry')
            chains.append({'current': current, 'witnessed_ancestry': chain})
        result = {'jid': jid, 'role': role, 'token_matches': True, 'processes': chains}
        if len(self.proofs) >= 8:
            raise ValueError('Too many session ancestry requests for one owning call')
        self.proofs.append(result)
        return result

    def log_deltas(self):
        values = {}
        for role, baseline in self.logs.items():
            path = Path(baseline['path'])
            if not path.exists():
                raw = b''
            else:
                info = path.stat()
                if baseline['inode'] is not None and info.st_ino != baseline['inode']:
                    raise ValueError('Salt role log rotated during the observation')
                if info.st_size < baseline['offset']:
                    raise ValueError('Salt role log shrank during the observation')
                with path.open('rb') as stream:
                    stream.seek(baseline['offset'])
                    raw = stream.read(MAX_BYTES + 1)
                if len(raw) > MAX_BYTES:
                    raise ValueError('Salt role log delta exceeds its 128-KiB bound')
            text = raw.decode(errors='replace')
            values[role] = dict(baseline, delta_base64=base64.b64encode(raw).decode(),
                               ret_key_errors=text.count("KeyError: 'ret'"),
                               tracebacks=text.count('Traceback (most recent call last):'),
                               worker_exceptions=text.count('An un-handled exception'))
        return values

    def report(self, jid=None):
        self.sample()
        returns = transient_cached_returns(jid, self.master_options, self.serial) if jid else {}
        return {'selector': self.selector, 'function': self.function, 'jid': jid,
                'expected_roles': self.expected,
                'role_options': {role: {key: opts.get(key) for key in ['id', 'cachedir', 'log_file', 'multiprocessing']}
                                 for role, opts in self.options.items()},
                'baseline_proc_names': {role: sorted(names) for role, names in self.baseline.items()},
                'jobs': self.jobs, 'returns': returns, 'logs': self.log_deltas(),
                'cache_reader': 'bounded_native_local_cache_envelopes',
                'witnessed_processes': self.lineage, 'session_proofs': self.proofs,
                'partial_reads': self.partial_reads, 'file_dropper_qualified': False}

    def finish(self, jid, seconds=30):
        if not re.fullmatch(r'[0-9]{20}', jid):
            raise ValueError('The owning/native publication did not provide one genuine JID')
        deadline = time.monotonic() + seconds
        negative_not_before = time.monotonic() + 2
        while True:
            report = self.report(jid)
            failures = []
            observed = report['jobs'].get(jid, {})
            if set(report['jobs']) - {jid}:
                failures.append('Unexpected matching publication JID observed')
            if set(observed) - set(self.expected):
                failures.append('Execution observed outside the selector')
            expected_ids = {self.options[role]['id'] for role in self.expected}
            if set(report['returns']) - expected_ids:
                failures.append('Master cache contains a node outside the selector')
            for role, entry in observed.items():
                if not entry['observed_live']:
                    failures.append('Missed live worker identity for ' + role)
                if entry['load'].get('ret') != '':
                    failures.append('Publication lacks native empty returner metadata')
                current = entry['worker_last']
                same = current['exists'] and current['starttime'] == entry['worker_live'].get('starttime')
                if same and current['state'] == 'Z' and current['wait_status'] != 0:
                    failures.append('Salt worker exited nonzero for ' + role)
                entry['worker_completed'] = not same or (current['state'] == 'Z' and current['wait_status'] == 0)
                entry['worker_completion'] = 'zombie_exit_zero' if same and entry['worker_completed'] else ('reaped_status_unavailable' if not same else 'running')
            for value in report['returns'].values():
                if value.get('success') is not True or value.get('retcode') != 0:
                    failures.append('Native master-cache envelope reports unsuccessful execution')
            if any(row['ret_key_errors'] or row['tracebacks'] or row['worker_exceptions'] for row in report['logs'].values()):
                failures.append('Salt role log contains a job exception')
            complete = (set(observed) == set(self.expected) and set(report['returns']) == expected_ids
                        and all(row['proc_absent'] and row['worker_completed'] for row in observed.values())
                        and (bool(self.expected) or time.monotonic() >= negative_not_before))
            if failures or complete or time.monotonic() >= deadline:
                missing = sorted(set(self.expected) - set(observed))
                if not complete and not failures:
                    failures.append('Completion observation timed out; missing live roles: ' + repr(missing))
                report.update(status='setup_failed' if missing else ('failed' if failures else 'passed'), failures=failures)
                return report
            time.sleep(POLL_SECONDS)


def observation_directory(identifier):
    if not re.fullmatch(r'[a-f0-9]{32}', identifier):
        raise ValueError('Invalid Salt observer identifier')
    return ROOT / identifier


def monitor(directory):
    config = json.loads((directory / 'configuration.json').read_text())
    observer = None
    result = {'status': 'setup_failed'}
    try:
        observer = JobObservation(config['selector'], config['function'])
        write_json(directory / 'ready.json', {'status': 'ready', 'worker': process(os.getpid()),
                                            'script_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                                            'expected_roles': observer.expected})
        deadline = time.monotonic() + 180
        while time.monotonic() < deadline:
            observer.sample()
            for request_path in (directory / 'requests').glob('*.json'):
                response = directory / 'responses' / request_path.name
                if response.exists():
                    continue
                request = json.loads(request_path.read_text())
                try:
                    proof = observer.proof(request['jid'], request['role'], request['pids'], request['token'])
                    write_json(response, {'status': 'passed', 'proof': proof})
                except (KeyError, ValueError) as error:
                    write_json(response, {'status': 'setup_failed', 'error': str(error)})
            if (directory / 'abort.json').exists():
                result = observer.report()
                result.update(status='aborted', failures=['Owning call aborted; completion is unqualified'])
                break
            if (directory / 'finish.json').exists():
                request = json.loads((directory / 'finish.json').read_text())
                result = observer.finish(request['jid'])
                break
            time.sleep(POLL_SECONDS)
        else:
            result = observer.report()
            result.update(status='setup_failed', failures=['Observer reached its absolute 180-second bound'])
    except Exception as error:
        result.update(status='setup_failed', error={'class': type(error).__name__, 'message': str(error)})
        if observer:
            result['jobs'] = observer.jobs
    finally:
        write_json(directory / 'finished.json', result)
    return 0 if result['status'] in ['passed', 'aborted'] else 1


def stop(directory, action, jid=None):
    if action not in ['finish', 'abort']:
        raise ValueError('Invalid Salt observer stop action')
    identity = observer_identity(directory)
    stop_error = None
    try:
        write_json(directory / (action + '.json'), {'jid': jid})
        wait_for(lambda: not same_running(identity), 40)
    except (OSError, ValueError, TimeoutError) as error:
        stop_error = {'class': type(error).__name__, 'message': str(error)}
    finally:
        if same_running(identity):
            signal_observer(identity, signal.SIGTERM)
            try:
                wait_for(lambda: not same_running(identity), 3)
            except TimeoutError:
                # Recheck PID/starttime immediately before this second signal.
                signal_observer(identity, signal.SIGKILL)
                wait_for(lambda: not same_running(identity), 3)
    terminal = directory / 'finished.json'
    result = json.loads(terminal.read_text()) if terminal.exists() else {
        'status': 'setup_failed', 'error': 'Observer terminated without a complete report'
    }
    result['observer_process'] = process(identity['pid'])
    result['observer_identity'] = identity
    result['observer_stopped'] = not same_running(identity)
    result['observer_identifier'] = directory.name
    if stop_error:
        result.update(status='setup_failed', stop_error=stop_error)
    return result


def observer_identity(directory):
    path = directory / 'ready.json'
    if not path.exists():
        path = directory / 'spawned.json'
    return json.loads(path.read_text())['worker']


def signal_observer(identity, operation):
    if same_running(identity):
        try:
            os.kill(identity['pid'], operation)
        except ProcessLookupError:
            pass


def export(directory):
    if same_running(observer_identity(directory)):
        raise RuntimeError('A live Salt observer cannot be exported or pruned')
    files = []
    total = 0
    for path in sorted(directory.rglob('*')):
        if path.is_symlink():
            raise ValueError('Unexpected symlink in the exact observer directory')
        if not path.is_file():
            continue
        raw = read_bytes(path, MAX_REPORT_BYTES)
        total += len(raw)
        if total > MAX_DIRECTORY_BYTES or len(files) >= 32:
            raise ValueError('Salt observer export exceeds its bounded directory budget')
        files.append({'name': str(path.relative_to(directory)),
                      'sha256': hashlib.sha256(raw).hexdigest(),
                      'bytes_base64': base64.b64encode(raw).decode()})
    return {'status': 'exported', 'observer_identifier': directory.name, 'files': files, 'bytes': total}


def observer_limits():
    # This applies only to the helper child, never to Salt or an owning payload.
    resource.setrlimit(resource.RLIMIT_FSIZE, (MAX_REPORT_BYTES, MAX_REPORT_BYTES))


def main():
    action = sys.argv[1]
    if action == 'monitor':
        return monitor(observation_directory(sys.argv[2]))
    if action == 'start':
        if ROOT.exists() and any(ROOT.iterdir()):
            raise RuntimeError('Previous observer evidence must be exported and pruned before another call')
        directory = observation_directory(uuid.uuid4().hex)
        directory.mkdir(parents=True, mode=0o700)
        (directory / 'requests').mkdir()
        (directory / 'responses').mkdir()
        write_json(directory / 'configuration.json', json.loads(sys.argv[2]))
        with (directory / 'monitor.log').open('wb') as log:
            child = subprocess.Popen([sys.executable, __file__, 'monitor', directory.name],
                                     stdin=subprocess.DEVNULL, stdout=log, stderr=log,
                                     close_fds=True, start_new_session=True, preexec_fn=observer_limits)
        write_json(directory / 'spawned.json', {'worker': process(child.pid)})
        try:
            wait_for(lambda: (directory / 'ready.json').exists() or child.poll() is not None, 20)
            if not (directory / 'ready.json').exists():
                raise RuntimeError('Salt observer failed before its ready handshake: ' + (directory / 'monitor.log').read_text())
            result = json.loads((directory / 'ready.json').read_text())
            if result['worker']['pid'] != child.pid or not same_running(result['worker']):
                raise RuntimeError('Ready observer identity is not the live spawned helper')
            result['observer_identifier'] = directory.name
        except Exception as error:
            if child.poll() is None:
                child.terminate()
                try:
                    child.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    child.kill()
                    child.wait(timeout=3)
            result = {'status': 'setup_failed', 'observer_identifier': directory.name,
                      'error': {'class': type(error).__name__, 'message': str(error)},
                      'observer_process': process(child.pid)}
            write_json(directory / 'start-failed.json', result)
    elif action == 'proof':
        directory = observation_directory(sys.argv[2])
        identifier = uuid.uuid4().hex + '.json'
        write_json(directory / 'requests' / identifier, json.loads(sys.argv[3]))
        response = directory / 'responses' / identifier
        wait_for(response.exists, 10)
        result = json.loads(response.read_text())
    elif action == 'export':
        result = export(observation_directory(sys.argv[2]))
    elif action == 'prune':
        directory = observation_directory(sys.argv[2])
        if directory.is_symlink() or same_running(observer_identity(directory)):
            raise RuntimeError('Refusing to prune a live or non-owned observer directory')
        shutil.rmtree(str(directory))
        result = {'status': 'pruned', 'observer_identifier': directory.name}
    else:
        result = stop(observation_directory(sys.argv[2]), action, sys.argv[3] if action == 'finish' else None)
    print('SALT_JOB_CONTROL=' + json.dumps(result, default=encode))
    return 0


if __name__ == '__main__':
    sys.exit(main())
