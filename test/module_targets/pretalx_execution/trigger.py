"""Observe genuine Celery completion, then start exactly one target interpreter."""
import hashlib
import datetime as dt
import json
from pathlib import Path
import re
import subprocess
import sys
import time

runtime = json.loads(Path(sys.argv[1]).read_text())
directory = Path(sys.argv[2])
directory.mkdir(exist_ok=True)
compose = runtime['compose']
before = set(json.loads((directory / 'before.json').read_text()))
user_site = sys.argv[3]
deadline = time.monotonic() + 80
state = {'phase': 'waiting_for_export', 'commands': []}
process = None
since = (dt.datetime.now(dt.timezone.utc) - dt.timedelta(seconds=5)).isoformat()


def save():
    target = directory / 'state.json'
    temporary = target.with_suffix('.tmp')
    temporary.write_text(json.dumps(state, indent=2) + '\n')
    temporary.replace(target)


def command(role, *args):
    result = subprocess.run(compose + ['exec', '-T', role, *args], capture_output=True, text=True, timeout=15)
    row = {'role': role, 'argv': args, 'exitstatus': result.returncode, 'stdout': result.stdout, 'stderr': result.stderr}
    with (directory / 'commands.jsonl').open('a') as output:
        output.write(json.dumps(row) + '\n')
    assert result.returncode == 0, row
    return result.stdout


try:
    target_id = subprocess.check_output(compose + ['ps', '-q', 'target'], text=True).strip()
    assert re.fullmatch(r'[0-9a-f]{64}', target_id)
    save()
    export_id = None
    while time.monotonic() < deadline:
        if (directory / 'stop').exists():
            state['phase'] = 'stopped_before_trigger'
            save()
            sys.exit(0)
        if export_id is None:
            logs = subprocess.run(['docker', 'logs', '--since', since, '--tail', '1000', target_id], capture_output=True, text=True, timeout=15)
            assert logs.returncode == 0, logs.stderr
            text = logs.stdout + logs.stderr
            identifiers = set(re.findall(r'(?:Received task: |Task )pretalx\.agenda\.tasks\.export_schedule_html\[([a-z0-9-]+)\]', text))
            identifiers = {value for value in identifiers if 'celery-task-meta-' + value not in before}
            if identifiers:
                assert len(identifiers) == 1, identifiers
                export_id = identifiers.pop()
                state['export_task_id'] = export_id
                state['export_worker_lines'] = [line for line in text.splitlines() if export_id in line]
                save()
        if export_id:
            data = command('broker', 'redis-cli', '--raw', '-n', '1', 'GET', 'celery-task-meta-' + export_id).strip()
            if data:
                task = json.loads(data)
                assert task['task_id'] == export_id
                if task['status'] in ['SUCCESS', 'FAILURE']:
                    state['export'] = task
                    break
        time.sleep(0.3)
    else:
        raise TimeoutError('No terminal export task was observed')

    output = command('target', 'sh', '-c', 'if test -d "$1"; then find "$1" -maxdepth 1 -type f -name "*.pth" -print; fi', 'native', user_site)
    state['hooks'] = output.splitlines()
    assert len(state['hooks']) <= 1, state['hooks']
    state['hook_contents'] = {name: command('target', 'cat', name) for name in state['hooks']}
    state['hook_sha256'] = {name: hashlib.sha256(content.encode()).hexdigest() for name, content in state['hook_contents'].items()}
    if not state['hooks']:
        state['phase'] = 'export_finished_without_hook'
        save()
        sys.exit(0)
    argv = compose + ['exec', '-T', 'target', 'python', '-c', 'pass']
    process = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    state.update(phase='trigger_started', argv=argv, pid=process.pid)
    save()
    try:
        output, error = process.communicate(timeout=80)
    except subprocess.TimeoutExpired:
        process.terminate()
        try:
            output, error = process.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            output, error = process.communicate()
        state['trigger_timed_out'] = True
    state.update(phase='trigger_terminal', actual_exit=process.returncode, stdout=output, stderr=error)
    save()
    assert not state.get('trigger_timed_out'), state
except Exception as error:
    state['error'] = str(error)
    save()
    raise
finally:
    if process is not None and process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()
