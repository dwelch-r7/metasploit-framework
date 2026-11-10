"""Require registered real YARN jobs, independent command execution and policy."""
import json
import os
from pathlib import Path
import re
import sys

sys.dont_write_bytecode = True
from native_client import NativeHadoop

runtime = json.loads(Path(os.environ['MODULE_TARGET_RUNTIME']).read_text())
client = NativeHadoop(runtime)
result = {}
admin = ('module-test-user', 'module-test-password')

try:
    cli = client.command('resourcemanager', 'hadoop', 'version')
    assert 'Hadoop 3.4.2\n' in cli['stdout'] and '84e8b89ee2ebe6923691205b9e171badde7a495c' in cli['stdout']
    identity = client.command('nodemanager', 'id')
    assert 'uid=1000(hadoop) gid=100(users)' in identity['stdout']
    assert client.command('nodemanager', 'which', 'base64')['stdout'] == '/usr/bin/base64\n'
    assert client.command('nodemanager', 'rpm', '-q', 'which')['stdout'].strip() == 'which-2.20-7.el7.x86_64'
    for bits, architecture, emulation in [('32', 'x86', 'elf_i386'), ('64', 'x64', 'elf_x86_64')]:
        executable = '/tmp/module-target-hadoop-elf-' + bits
        try:
            client.command('nodemanager', 'as', '--' + bits, '-o', executable + '.o', '/lab/native' + bits + '.S')
            client.command('nodemanager', 'ld', '-m', emulation, '-o', executable, executable + '.o')
            binary = client.command('nodemanager', executable)
            assert binary['stdout'] == 'Native Linux ' + architecture + ' ELF\n', binary
        finally:
            client.command('nodemanager', 'rm', '-f', executable, executable + '.o')
            client.command('nodemanager', 'test', '!', '-e', executable)
    code, info, raw = client.request('resourcemanager', '/ws/v1/cluster/info')
    assert code == 200 and info['clusterInfo']['resourceManagerVersion'] == '3.4.2' and info['clusterInfo']['state'] == 'STARTED', raw
    client.wait(client.idle, timeout=45)
    nodes = client.command('resourcemanager', 'yarn', 'node', '-list', '-all')
    assert 'Total Nodes:1' in nodes['stdout'] and 'RUNNING' in nodes['stdout']
    def hdfs_ready():
        report = client.command('namenode', 'hdfs', 'dfsadmin', '-report')
        return report if 'Live datanodes (1)' in report['stdout'] and 'Missing blocks: 0' in report['stdout'] else None
    hdfs = client.wait(hdfs_ready, timeout=45)
    jar = '/opt/hadoop/share/hadoop/yarn/hadoop-yarn-applications-distributedshell-3.4.2.jar'
    jobs = []
    for number in (1, 2):
        path = f'/tmp/module-target-hadoop-native-job-{number}'
        client.command('nodemanager', 'test', '!', '-e', path)
        try:
            job = client.command('resourcemanager', 'yarn', 'jar', jar, 'org.apache.hadoop.yarn.applications.distributedshell.Client',
                                 '--jar', jar, '--appname', f'module-target-native-{number}', '--shell_command', '/bin/touch', '--shell_args', path,
                                 '--num_containers', '1', '--master_memory', '256', '--container_memory', '128', '--timeout', '90000', timeout=120)
            assert 'Application completed successfully' in job['stdout'] + job['stderr'], job
            app = re.search(r'application_\d+_\d+', job['stdout'] + job['stderr']).group()
            code, document, raw = client.request('resourcemanager', f'/ws/v1/cluster/apps/{app}')
            assert code == 200 and document['app']['state'] == 'FINISHED' and document['app']['finalStatus'] == 'SUCCEEDED', raw
            assert client.command('nodemanager', 'stat', '-c', '%u:%g:%s', path)['stdout'].strip() == '1000:100:0'
            jobs.append(dict(application=app, seconds=job['seconds'], state=document['app']['state']))
        finally:
            client.command('nodemanager', 'rm', '-f', path)
            client.command('nodemanager', 'test', '!', '-e', path)
            client.wait(client.idle)
    markers = [client.marker('resourcemanager', '/', str(n)) for n in (1, 2)]
    markers.append(client.marker('gateway', '/yarn/', 'prefix'))
    markers.append(client.marker('gateway', '/secured/', 'basic', admin))
    for credentials in (None, ('module-test-user', 'wrong-password')):
        code, _, raw = client.request('gateway', '/secured/ws/v1/cluster/apps/new-application', method='POST', auth=credentials)
        assert code == 401, raw
    for service, path, expected in [('gateway', '/denied/ws/v1/cluster/apps/new-application', 403),
                                     ('gateway', '/missing/ws/v1/cluster/apps/new-application', 404),
                                     ('unrelated', '/ws/v1/cluster/apps/new-application', 404)]:
        code, _, raw = client.request(service, path, method='POST')
        assert code == expected, (code, raw)
    result = dict(cli=cli['stdout'], identity=identity['stdout'], cluster=info['clusterInfo'], jobs=jobs, markers=markers)
    print(json.dumps(result))
finally:
    client.write(Path(runtime['artifacts']) / 'native-hadoop-controls.json', result=result)
