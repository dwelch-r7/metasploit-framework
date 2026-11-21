"""Supervise unmodified Salt master/API daemons with ordinary TLS configuration."""

from pathlib import Path
import json
import os
import signal
import subprocess
import time
import uuid

import yaml


def main():
    processes = []
    stopping = {'requested': False}
    state = {'roles': {}}

    def stop(number, frame):
        stopping['requested'] = True

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    for directory in ['/etc/salt/pki', '/var/cache/salt', '/var/run/salt', '/var/log/salt', '/srv/salt', '/srv/pillar']:
        Path(directory).mkdir(parents=True, exist_ok=True)
    cert, key = '/var/run/salt/api.crt', '/var/run/salt/api.key'
    subprocess.run(['openssl', 'req', '-x509', '-nodes', '-newkey', 'rsa:2048', '-days', '1', '-subj', '/CN=module-target-salt-api', '-keyout', key, '-out', cert], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    prefix = os.environ.get('SALT_API_PREFIX', '/')
    assert prefix.startswith('/') and '..' not in prefix
    base = yaml.safe_load(Path('/etc/salt/master').read_text())
    base.update(sharedsecret='module-target-salt-api-password', external_auth={'sharedsecret': {'nativefixture': ['test.*', '@runner', '@wheel']}})
    base['rest_cherrypy'] = dict(port=8000, host='0.0.0.0', ssl_crt=cert, ssl_key=key, root_prefix=prefix, thread_pool=4)
    Path('/etc/salt/roster').write_text('{}\n')
    try:
        for role in ['master', 'api']:
            options = dict(base)
            if role == 'api':
                # Login tokens are minted by the master and validated by the
                # API. Ordinary deployments share their cache and PKI paths.
                options.update(pidfile='/var/run/salt/api.pid', api_pidfile='/var/run/salt/api.pid', log_file='/var/log/salt/api')
            directory = Path('/var/run/salt') / (role + '-config')
            directory.mkdir()
            config = directory / 'master'
            config.write_text(yaml.safe_dump(options))
            config.chmod(0o600)
            # Salt resolves the default roster relative to each daemon's own
            # configuration directory. Keep both native defaults valid.
            (directory / 'roster').write_text('{}\n')
            token = uuid.uuid4().hex
            environment = dict(os.environ, MSF_MODULE_TARGET_ROLE=role, MSF_MODULE_TARGET_TOKEN=token)
            command = ['salt-' + role, '--log-level=warning', '--config-dir=' + str(directory)]
            process = subprocess.Popen(command, env=environment, start_new_session=True)
            processes.append(process)
            state['roles'][role] = dict(pid=process.pid, token=token, command=command, config=str(config))
        Path('/var/run/salt/module-target-api.json').write_text(json.dumps(dict(state, prefix=prefix), indent=2) + '\n')
        while not stopping['requested'] and all(process.poll() is None for process in processes):
            time.sleep(0.2)
    finally:
        for process in processes:
            if process.poll() is None:
                try:
                    os.killpg(process.pid, signal.SIGTERM)
                except ProcessLookupError:
                    pass
        deadline = time.monotonic() + 5
        for process in processes:
            if process.poll() is None:
                try:
                    process.wait(timeout=max(0, deadline - time.monotonic()))
                except subprocess.TimeoutExpired:
                    os.killpg(process.pid, signal.SIGKILL)
                    process.wait()
    return 0 if stopping['requested'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
