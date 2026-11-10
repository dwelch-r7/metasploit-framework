"""Genuine file-URL H2 controls, separately captured from Framework execution."""

from pathlib import Path
import json
import os
import re
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "nifi_execution"))
from api import NativeClient, NifiTarget, wait_until
from actions import seed, snapshot, restore, verify_canary


def await_proof(target, path):
    return wait_until(lambda: (lambda value: value if value.startswith('uid=1000(nifi)') else None)(target.execute('sh', '-c', 'if test -f ' + path + '; then cat ' + path + '; fi').decode()))


def h2_control(target):
    jars = target.execute('find', '/opt/nifi/nifi-toolkit-current/lib', '-name', 'h2*.jar', '-print').decode().splitlines()
    assert len(jars) == 1, jars
    jar = jars[0]
    digest = target.execute('sha256sum', jar).decode().strip()
    actual_version = target.execute('java', '-cp', jar, 'org.h2.tools.Shell', '-url', 'jdbc:h2:mem:module_target_native', '-user', 'sa', '-password', '', '-sql', 'SELECT H2VERSION();').decode()
    expected_version = '1.4.199' if target.service == 'legacy' else '2.1.214'
    assert expected_version in actual_version, actual_version
    path = '/tmp/module-target-native-h2-proof'
    prefix = '/tmp/module-target-native-file-h2-' + target.service + '.db'
    target.execute('test', '!', '-e', path)
    before = target.graph()
    files_before = target.execute('find', '/tmp', '-maxdepth', '1', '-name', Path(prefix).name + '*', '-printf', '%p\n').decode().splitlines()
    assert files_before == [], files_before
    controller = processor = None
    result = {'jar': jar, 'jar_sha256sum': digest, 'actual_h2_version': actual_version, 'database_prefix': prefix}
    try:
        created = target.create('controller-services', 'Native file H2 policy control', 'org.apache.nifi.dbcp.DBCPConnectionPool')
        controller = created['id']
        url = 'jdbc:h2:file:' + prefix + ';TRACE_LEVEL_SYSTEM_OUT=0\\;CREATE TRIGGER NATIVE_FILE_PROOF BEFORE SELECT ON INFORMATION_SCHEMA.TABLES AS $$//javascript\nnew java.lang.ProcessBuilder("/bin/sh","-c","id > ' + path + '").start().waitFor()\n$$--=x'
        status, _, raw = target.request('/nifi-api/controller-services/' + controller, method='PUT', data={'revision': created['revision'], 'component': {'id': controller, 'properties': {'Database Connection URL': url, 'Database Driver Class Name': 'org.h2.Driver', 'database-driver-locations': jar, 'Max Total Connections': '1'}}})
        assert status == 200, (status, raw)
        current = wait_until(lambda: (lambda item: item if item['component']['validationStatus'] in ('VALID', 'INVALID') else None)(target.entity('controller-services', controller)))
        result['validation'] = current
        if target.service == 'fixed':
            assert current['component']['validationStatus'] == 'INVALID', current
            assert any('unsupported scheme [jdbc:h2]' in value for value in current['component']['validationErrors']), current
            target.execute('test', '!', '-e', path)
        else:
            assert current['component']['validationStatus'] == 'VALID', current
            target.run_state('controller-services', controller, 'ENABLED')
            wait_until(lambda: target.quiescent('controller-services', controller, 'ENABLED'))
            created = target.create('processors', 'Native file H2 execution proof', 'org.apache.nifi.processors.standard.ExecuteSQL')
            processor = created['id']
            status, _, raw = target.request('/nifi-api/processors/' + processor, method='PUT', data={'revision': created['revision'], 'component': {'id': processor, 'config': {'properties': {'Database Connection Pooling Service': controller, 'SQL select query': 'SELECT H2VERSION() FROM DUAL;'}, 'autoTerminatedRelationships': ['success', 'failure'], 'schedulingPeriod': '3600 sec'}}})
            assert status == 200, (status, raw)
            wait_until(lambda: (lambda item: item if item['component']['validationStatus'] == 'VALID' else None)(target.entity('processors', processor)))
            target.run_state('processors', processor, 'RUNNING')
            result['proof'] = await_proof(target, path)
    finally:
        if processor:
            target.remove('processors', processor)
        if controller:
            target.remove('controller-services', controller)
        result['files_after_native_service_removal'] = target.execute('find', '/tmp', '-maxdepth', '1', '-name', Path(prefix).name + '*', '-printf', '%p\n').decode().splitlines()
        for filename in result['files_after_native_service_removal']:
            assert filename.startswith(prefix)
            target.execute('rm', filename)
        target.execute('rm', '-f', path)
        assert target.graph() == before
        result['operator_restoration'] = True
    return result


def main():
    action, service, tag = sys.argv[1:4]
    if not tag.replace('_', '').replace('-', '').isalnum():
        raise ValueError('Invalid native artifact tag')
    runtime = json.loads(Path(os.environ['MODULE_TARGET_RUNTIME']).read_text())
    client = NativeClient(runtime, 'native-h2-' + tag + '.json')
    facts_file = Path(runtime['artifacts']) / 'nifi-h2-facts.json'
    try:
        if action == 'preflight':
            target = NifiTarget(client, service)
            facts = target.verify()
            facts['identity'] = target.execute('id').decode().strip()
            assert facts['identity'].startswith('uid=1000(nifi) gid=1000(nifi)'), facts
            target.execute('java', '-version')
            facts['canary'] = seed(target)
            facts['native_h2'] = h2_control(target)
            facts['initial_snapshot'] = snapshot(target)
            facts_file.write_text(json.dumps(facts, indent=2) + '\n')
            return facts
        facts = json.loads(facts_file.read_text())
        target = NifiTarget(client, service, token=facts['token'])
        if action == 'snapshot':
            return snapshot(target)
        if action == 'restore':
            return restore(target, json.loads(sys.argv[4]), json.loads(sys.argv[5]))
        if action == 'verify-canary':
            return verify_canary(target, facts, client)
        if action == 'restore-db-files':
            paths = json.loads(sys.argv[4])
            removed = []
            for path in paths:
                assert re.fullmatch(r'/tmp/[A-Za-z0-9]{6,10}\.db\.(?:mv\.db|trace\.db|lock\.db)', path), path
                identity = target.execute('stat', '-c', '%u:%g:%F', path).decode().strip()
                assert identity == '1000:1000:regular file', identity
                digest = target.execute('sha256sum', path).decode().strip()
                target.execute('rm', path)
                removed.append({'path': path, 'identity': identity, 'sha256sum': digest})
            return {'kind': 'Explicit operator removal of newly observed declared H2 file-database artifacts', 'removed': removed}
        raise ValueError('Unknown H2 native action ' + action)
    finally:
        client.save()


if __name__ == '__main__':
    print(json.dumps(main()))
