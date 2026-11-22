"""Observe real generated commands in a persistent interpreter, then clean up."""

import base64
import errno
import json
import os
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time


PROOF = b'python-exec-\x00\xe2\x98\x83\r\n'


def descriptor_state():
    directory = '/dev/fd' if os.path.isdir('/dev/fd') else '/proc/self/fd'
    descriptors = {}
    for name in os.listdir(directory):
        try:
            details = os.fstat(int(name))
        except OSError as error:
            if error.errno == errno.EBADF:
                continue
            raise
        descriptors[name] = [details.st_dev, details.st_ino, details.st_mode]
    return descriptors


def child(mode, label):
    # A failing original payload must not leave an indefinitely blocked child.
    signal.alarm(6)
    peer = socket.create_connection(('127.0.0.1', int(os.environ['PYTHON_EXEC_PROBE_PORT'])), 3)
    peer.sendall((json.dumps({'pid': os.getpid(), 'ppid': os.getppid(), 'label': label}) + '\n').encode('ascii'))
    if peer.recv(1) != b'x':
        raise RuntimeError('Child did not receive its release token')
    stdin_eof = None
    if mode == 'pipes':
        stdin_eof = sys.stdin.read() == ''
        sys.stdout.write('o' * 262144)
        sys.stdout.flush()
        sys.stderr.write('e' * 262144)
        sys.stderr.flush()
    path = os.path.join(os.environ['PYTHON_EXEC_PROBE_DIRECTORY'], label)
    with open(path, 'wb') as output:
        output.write(PROOF)
    peer.sendall((json.dumps({'complete': True, 'stdin_eof': stdin_eof}) + '\n').encode('ascii'))
    peer.close()
    signal.alarm(0)


def automatic_reaping(pid):
    deadline = time.time() + 2
    while True:
        try:
            waited, status = os.waitpid(pid, os.WNOHANG)
        except OSError as error:
            if error.errno != errno.ECHILD:
                raise
            return {'automatic': True, 'probe_reaped': False}
        if waited:
            # This observes the failure and reaps that exact local baseline
            # child. It must never be reported as automatic payload cleanup.
            return {'automatic': False, 'probe_reaped': True, 'status': status}
        if time.time() >= deadline:
            return {'automatic': False, 'probe_reaped': False, 'still_running': True}
        threading.Event().wait(0.01)


def run(document):
    initial_descriptors = descriptor_state()
    directory = tempfile.mkdtemp(prefix='python-exec-lifecycle-')
    os.environ['PYTHON_EXEC_PROBE_DIRECTORY'] = directory
    listener = socket.socket()
    listener.bind(('127.0.0.1', 0))
    listener.listen(len(document['payloads']))
    listener.settimeout(3)
    os.environ['PYTHON_EXEC_PROBE_PORT'] = str(listener.getsockname()[1])
    before_descriptors = descriptor_state()
    before_threads = set(threading.enumerate())
    before_processes = set(getattr(subprocess, '_active', []))
    namespace = {}
    invokers, records, waiters, errors = [], [], [], []

    def invoke(program, returned):
        try:
            exec(compile(program, '<real-python-exec-payload>', 'exec'), namespace)
        except Exception as error:
            errors.append(str(error))
        finally:
            returned.set()

    try:
        for program in document['payloads']:
            returned = threading.Event()
            invoker = threading.Thread(target=invoke, args=(program, returned))
            invoker.daemon = True
            invokers.append(invoker)
            invoker.start()
            peer, _ = listener.accept()
            peer.settimeout(2)
            reader = peer.makefile('rb')
            metadata = json.loads(reader.readline().decode('ascii'))
            if metadata['ppid'] != os.getpid():
                raise RuntimeError('Expected the exec command to remain a direct child')
            returned.wait(0.5)
            records.append({'process': metadata, 'returned_before_release': returned.is_set(), 'peer': peer, 'reader': reader})
        waiters = [worker for worker in threading.enumerate() if worker not in before_threads and worker not in invokers]
        # A background waiter must own its original process rather than look
        # up payload temporaries again in the persistent application's globals.
        namespace.update({'args': ['poisoned-after-return'], 'process': None, 'waiter': None})
        for record in records:
            record['peer'].sendall(b'x')
        for record in records:
            try:
                line = record['reader'].readline()
                record['completion'] = json.loads(line.decode('ascii')) if line else None
            except socket.timeout:
                record['completion'] = None
            finally:
                record.pop('reader').close()
                record.pop('peer').close()
        for invoker in invokers:
            invoker.join(3)
        for waiter in waiters:
            waiter.join(3)
        for record in records:
            record['reaping'] = automatic_reaping(record['process']['pid'])
            path = os.path.join(directory, record['process']['label'])
            record['proof_base64'] = None
            if os.path.exists(path):
                with open(path, 'rb') as proof:
                    record['proof_base64'] = base64.b64encode(proof.read()).decode('ascii')
        result = {
            'interpreter': sys.version,
            'host_pid': os.getpid(),
            'records': records,
            'waiters_daemon': all(worker.daemon for worker in waiters),
            'waiters_finished': all(not worker.is_alive() for worker in waiters),
            'invokers_finished': all(not worker.is_alive() for worker in invokers),
            'descriptors_preserved': descriptor_state() == before_descriptors,
            'errors': errors,
        }
    finally:
        for record in records:
            if 'reader' in record:
                record.pop('reader').close()
            if 'peer' in record:
                record.pop('peer').close()
        # No new Popen may be used for observation: its implicit _cleanup()
        # would reap the original payload and conceal the measured zombie.
        # Touch _active only after recording the result, for local test cleanup.
        for process in list(getattr(subprocess, '_active', [])):
            if process in before_processes:
                continue
            for stream in [process.stdin, process.stdout, process.stderr]:
                if stream is not None:
                    stream.close()
            process.wait()
            if process in subprocess._active:
                subprocess._active.remove(process)
        for record in records:
            try:
                os.waitpid(record['process']['pid'], 0)
            except OSError as error:
                if error.errno != errno.ECHILD:
                    raise
        for worker in invokers + waiters:
            worker.join(3)
        listener.close()
        shutil.rmtree(directory)
    result['cleanup_descriptors_preserved'] = descriptor_state() == initial_descriptors
    try:
        os.waitpid(-1, os.WNOHANG)
    except OSError as error:
        if error.errno != errno.ECHILD:
            raise
        result['no_children_after_cleanup'] = True
    else:
        result['no_children_after_cleanup'] = False
    return result


if __name__ == '__main__':
    if len(sys.argv) > 1 and sys.argv[1] == 'child':
        child(sys.argv[2], sys.argv[3])
    else:
        print(json.dumps(run(json.load(sys.stdin))))
