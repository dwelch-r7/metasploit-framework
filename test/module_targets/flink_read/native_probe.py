"""Independently prove genuine Flink versions, permissions, jobs and cleanup."""
import base64
import hashlib
import json
import os
from pathlib import Path
import time
import urllib.parse
from native_client import NativeFlink

runtime = json.loads(Path(os.environ['MODULE_TARGET_RUNTIME']).read_text())
client = NativeFlink(runtime)
profiles = {}
artifacts = Path(runtime['artifacts'])
started = time.monotonic()
try:
    for service, version in [('vulnerable', '1.11.2'), ('fixed', '1.11.3'), ('disabled', '1.11.2')]:
        cli = client.command(service, '/opt/flink/bin/flink', '--version').stdout.decode()
        java = client.command(service, 'java', '-version').stderr.decode()
        init_name = client.command(service, 'cat', '/proc/1/comm').stdout.strip()
        assert init_name in [b'docker-init', b'tini'], init_name
        java_pids = client.command(service, 'sh', '-c', 'for item in /proc/[0-9]*/comm; do read -r name < "$item" || continue; if [ "$name" = java ]; then prefix=${item%/comm}; printf "%s\\n" "${prefix##*/}"; fi; done').stdout.decode().splitlines()
        assert len(java_pids) == 1 and java_pids[0].isdigit(), java_pids
        server_pid = java_pids[0]
        server_status = client.command(service, 'cat', '/proc/'+server_pid+'/status').stdout.decode()
        uid = next(line for line in server_status.splitlines() if line.startswith('Uid:'))
        server_command = client.command(service, 'cat', '/proc/'+server_pid+'/cmdline').stdout
        assert b'org.apache.flink.runtime.entrypoint.StandaloneSessionClusterEntrypoint' in server_command
        conf = client.command(service, 'cat', '/opt/flink/conf/flink-conf.yaml').stdout.decode()
        assert f'Version: {version},' in cli and '1.8.0_' in java
        assert uid.split()[1:] == ['9999']*4, uid
        status, config, _ = client.request(service, '/config')
        assert status == 200 and config['flink-version'] == version
        jars_code, jars, _ = client.request(service, '/jars')
        if service == 'disabled':
            assert jars_code == 404
        else:
            assert jars_code == 200 and jars['files'] == []
        profiles[service] = dict(version=version, cli=cli, java=java, uid=uid, config=config, configuration=conf, server_pid=server_pid, server_status=server_status, server_command_base64=base64.b64encode(server_command).decode(), init_name=init_name.decode())
        assert client.command(service, 'gosu', 'flink', 'cat', '/root/module-target-protected', check=False).returncode == 1
        for path in ['/opt/flink/fixtures/public.txt', '/opt/flink/fixtures/nested/space name.txt', '/opt/flink/fixtures/empty.txt', '/root/module-target-protected', '/opt/flink/fixtures/missing.txt']:
            encoded = urllib.parse.quote(urllib.parse.quote('../'*10+path, safe=''), safe='')
            code, doc, body = client.request(service, '/jobmanager/logs/'+encoded)
            profiles[service].setdefault('files', {})[path] = dict(code=code, body_base64=base64.b64encode(body).decode())
            if service != 'fixed' and path.startswith('/opt/flink/fixtures/') and 'missing' not in path:
                native = client.command(service, 'gosu', 'flink', 'cat', path).stdout
                assert code == 200 and body == native, (service, path, code, doc)
            else:
                assert code in [404, 500] and b'module-target-flink-protected' not in body, (service, path, code)
    auth = ('module-test-user', 'module-test-password')
    status, gateway_config, _ = client.request('gateway', '/flink/config', auth=auth)
    assert status == 200 and gateway_config == profiles['vulnerable']['config']
    for credentials in [None, (auth[0], 'wrong-password')]:
        assert client.request('gateway', '/flink/config', auth=credentials)[0] == 401
    for depth in [1, 10]:
        raw = ('../'*depth+'/opt/flink/fixtures/public.txt').encode()
        first = ''.join(f'%{byte:02x}' for byte in raw)
        encoded = ''.join(f'%{byte:02x}' for byte in first.encode())
        code, _, body = client.request('gateway', '/flink/jobmanager/logs/'+encoded, auth=auth)
        assert code == (200 if depth == 10 else 404), (depth, code, body)
        if depth == 10:
            assert body == client.command('vulnerable', 'gosu', 'flink', 'cat', '/opt/flink/fixtures/public.txt').stdout
    assert client.request('vulnerable', '/module-target-missing/config')[0] == 404
    assert client.request('unrelated', '/config')[0] == 404
    assert client.request('unrelated', '/')[2].find(b'module-target-http-marker') >= 0

    if os.environ.get('FLINK_TARGET_PROFILE', 'exec') == 'exec':
        jar_path = artifacts/'native-WordCount.jar'
        client.process(runtime['compose']+['cp', 'vulnerable:/opt/flink/examples/batch/WordCount.jar', str(jar_path)])
        jar = jar_path.read_bytes()
        assert jar.startswith(b'PK')
        for service, backend, worker, prefix, credentials in [('vulnerable','vulnerable','vulnerable_worker','',None), ('fixed','fixed','fixed_worker','',None), ('gateway','vulnerable','vulnerable_worker','/flink',auth)]:
            for repetition in range(2):
                before = client.request(service, prefix+'/jars', auth=credentials)[1]
                assert before['files'] == []
                output = '/tmp/module-target-native-wordcount'
                assert client.command(worker, 'test', '!', '-e', output).returncode == 0
                code, uploaded, _ = client.upload(service, 'native-WordCount.jar', jar, prefix, credentials)
                assert code == 200 and uploaded['status'] == 'success', (code, uploaded)
                jars = client.request(service, prefix+'/jars', auth=credentials)[1]['files']
                assert len(jars) == 1 and jars[0]['name'] == 'native-WordCount.jar', jars
                jar_id = jars[0]['id']
                code, result, _ = client.request(service, prefix+'/jars/'+jar_id+'/run', method='POST', auth=credentials,
                    data=dict(entryClass='org.apache.flink.examples.java.wordcount.WordCount', parallelism=1,
                              programArgsList=['--input','/lab/native-input.txt','--output',output]))
                assert code == 200 and len(result['jobid']) == 32, (code, result)
                deadline = time.monotonic()+40
                while True:
                    job = client.request(service, prefix+'/jobs/'+result['jobid'], auth=credentials)[1]
                    if job['state'] == 'FINISHED':
                        break
                    assert job['state'] not in ['FAILED','CANCELED'] and time.monotonic() < deadline, job
                    time.sleep(0.2)
                actual = client.command(worker, 'cat', output).stdout.decode()
                assert sorted(actual.splitlines()) == ['flink 2','module 1'], actual
                assert client.command(worker, 'stat', '-c', '%U', output).stdout.strip() == b'flink'
                assert client.request(service, prefix+'/jars/'+jar_id, method='DELETE', auth=credentials)[0] == 200
                assert client.request(service, prefix+'/jars', auth=credentials)[1]['files'] == []
                assert client.command(backend, 'find', '/opt/flink/uploads', '-mindepth', '1', '-type', 'f', '-print').stdout == b''
                client.command(worker, 'rm', output)
                client.command(worker, 'test', '!', '-e', output)
                profiles.setdefault('jobs', []).append(dict(service=service, repetition=repetition, job=result, state=job['state'], output=actual, jar_sha256=hashlib.sha256(jar).hexdigest()))
        disabled_before = client.upload_state('disabled')
        assert disabled_before['files'] == []
        assert client.upload('disabled', 'native-WordCount.jar', jar)[0] == 404
        disabled_after = client.upload_state('disabled')
        staged = disabled_after['files']
        assert len(staged) == 1 and Path(staged[0]).name == 'native-WordCount.jar', staged
        assert client.command('disabled', 'cat', staged[0]).stdout == jar
        assert client.command('disabled', 'stat', '-c', '%U', staged[0]).stdout.strip() == b'flink'
        profiles['disabled_upload'] = dict(status=404, captured_file=staged[0], sha256=hashlib.sha256(jar).hexdigest(),
            restoration=client.restore_staging('disabled', disabled_before, staged))
        for credentials in [None, (auth[0], 'wrong-password')]:
            assert client.upload('gateway', 'native-WordCount.jar', jar, '/flink', credentials)[0] == 401
        assert client.request('vulnerable', '/jars')[1]['files'] == []
        assert client.request('fixed', '/jars')[1]['files'] == []
finally:
    client.write(artifacts/'native-flink-partial.json', profiles=profiles, seconds=time.monotonic()-started)
print(json.dumps(dict(commands=client.commands, requests=client.requests, profiles=profiles, seconds=time.monotonic()-started), indent=2))
