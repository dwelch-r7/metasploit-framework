"""Supervise ordinary Salt daemons with distinct execution-proof environments."""
import json
import os
from pathlib import Path
import signal
import subprocess
import time
import uuid

import yaml


def main():
    processes = []
    stopping = {'requested': False}
    state = {'roles': {}}

    def stop(signum, frame):
        stopping['requested'] = True

    def start(role, argv, config):
        # Co-located nodes share a hostname; inherited tokens prove which
        # daemon actually executed a command or opened a session.
        token = uuid.uuid4().hex
        environment = dict(os.environ, MSF_MODULE_TARGET_ROLE=role,
                           MSF_MODULE_TARGET_TOKEN=token)
        process = subprocess.Popen(argv, env=environment, start_new_session=True)
        processes.append(process)
        state['roles'][role] = {'pid': process.pid, 'token': token,
                                'argv': argv, 'config': config}

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    try:
        start('master', ['salt-master', '--log-level=warning', '--config-dir=/etc/salt'], '/etc/salt/master')
        template = yaml.safe_load(Path('/opt/module-target/minion-template').read_text())
        for suffix in ['a', 'b']:
            role = 'minion-' + suffix
            directory = Path('/var/run/salt') / (role + '-config')
            directory.mkdir()
            options = dict(template, id='module-target-' + role,
                           cachedir='/var/cache/salt/' + role,
                           pki_dir='/etc/salt/pki/' + role,
                           sock_dir='/var/run/salt/' + role,
                           pidfile='/var/run/salt/' + role + '.pid',
                           log_file='/var/log/salt/' + role)
            (directory / 'minion').write_text(yaml.safe_dump(options))
            start(role, ['salt-minion', '--log-level=warning', '--config-dir=' + str(directory)],
                  str(directory / 'minion'))
        path = Path('/var/run/salt/module-target.json')
        path.write_text(json.dumps(state, indent=2) + '\n')
        path.chmod(0o600)
        while not stopping['requested'] and all(process.poll() is None for process in processes):
            time.sleep(0.2)
    finally:
        for process in processes:
            if process.poll() is None:
                try:
                    os.killpg(process.pid, signal.SIGTERM)
                except ProcessLookupError:
                    process.wait()
        deadline = time.monotonic() + 5
        for process in processes:
            if process.poll() is None:
                try:
                    process.wait(timeout=max(0, deadline - time.monotonic()))
                except subprocess.TimeoutExpired:
                    try:
                        os.killpg(process.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    process.wait()
    return 0 if stopping['requested'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
