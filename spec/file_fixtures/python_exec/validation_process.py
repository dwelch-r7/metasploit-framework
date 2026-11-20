"""Real Python/process control at Langflow 1.8.4's FunctionDef boundary."""

import ast
import json
import os
import socket
import subprocess
import sys
import threading
import time


def process_state(pid):
    result = subprocess.run(['ps', '-p', str(pid), '-o', 'stat='], capture_output=True, text=True, check=False)
    if result.returncode not in (0, 1) or result.stderr or (result.returncode == 0) != bool(result.stdout.strip()):
        raise RuntimeError(f'Failed to inspect process {pid}: {result}')
    return result.stdout.strip()


def attempt(code):
    listener = socket.socket()
    listener.bind(('127.0.0.1', 0))
    listener.listen(1)
    listener.settimeout(5)
    os.environ['LANGFLOW_EXECUTION_PROBE_PORT'] = str(listener.getsockname()[1])
    returned = threading.Event()
    errors = []
    baseline_threads = set(threading.enumerate())

    def validate():
        try:
            for node in ast.parse(code).body:
                if isinstance(node, ast.FunctionDef):
                    exec(compile(ast.Module(body=[node], type_ignores=[]), '<validation>', 'exec'), {'validation_context': object()})
        except Exception as error:
            errors.append(str(error))
        finally:
            returned.set()

    validator = threading.Thread(target=validate)
    validator.start()
    connection = None
    workers = []
    try:
        connection, _ = listener.accept()
        connection.settimeout(5)
        with connection.makefile('rb') as reader:
            proof = json.loads(reader.readline())
        returned_before_release = returned.wait(1)
        workers = [worker for worker in threading.enumerate() if worker not in baseline_threads and worker is not validator]
        connection.sendall(b'x')
        eof = connection.recv(1) == b''
    finally:
        if connection is not None:
            connection.close()
        listener.close()
        validator.join(5)
        for worker in workers:
            worker.join(5)

    deadline = time.monotonic() + 3
    state = process_state(proof['pid'])
    while state and not state.startswith('Z') and time.monotonic() < deadline:
        threading.Event().wait(0.05)
        state = process_state(proof['pid'])
    launch_reaped = False
    if proof['launch_pid'] != os.getpid():
        try:
            os.waitpid(proof['launch_pid'], os.WNOHANG)
        except ChildProcessError:
            launch_reaped = True

    # Preserve the original owner's measured zombie result, then reap the local
    # control's direct child so a deliberately failing regression leaks nothing.
    if proof['launch_pid'] == os.getpid() and proof['pid'] != os.getpid():
        os.waitpid(proof['pid'], 0)

    return {
        'validator_pid': os.getpid(),
        'process': proof,
        'returned_before_release': returned_before_release,
        'isolated': proof['isolated'],
        'separate_process': proof['launch_pid'] != os.getpid(),
        'worker_finished': all(not worker.is_alive() for worker in workers),
        'launch_reaped': launch_reaped,
        'process_absent': state == '',
        'observed_state': state,
        'eof': eof,
        'errors': errors,
    }


request = json.load(sys.stdin)
os.environ['LANGFLOW_EXECUTION_FORK'] = str(request['fork']).lower()
print(json.dumps([attempt(code) for code in request['codes']]))
