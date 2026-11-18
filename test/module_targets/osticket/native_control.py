"""Independent installer, authentication, PDF and upstream PoC controls."""
from pathlib import Path
import hashlib,json,os,subprocess,sys

runtime=json.loads(Path(sys.argv[1]).read_text())
out=Path(runtime['directory']);out.mkdir(exist_ok=True)
report={'owner_loaded':False,'commands':[],'phase':runtime['phase'],'passed':False}
env=dict(os.environ,DOCKER_CONTEXT=os.environ.get('DOCKER_CONTEXT','default'))
here=Path(__file__).parent

def save():
 (out/'native-proof.json').write_text(json.dumps(report,indent=2)+'\n')

def command(label,argv,data=None):
 p=subprocess.run(argv,input=data,capture_output=True,env=env,timeout=180)
 (out/(label+'.stdout')).write_bytes(p.stdout);(out/(label+'.stderr')).write_bytes(p.stderr)
 report['commands'].append({'label':label,'argv':argv,'exit':p.returncode});save()
 if p.returncode:raise RuntimeError('Native control failed: '+label+': '+p.stderr.decode(errors='replace')[-1500:])
 return p.stdout

def control(action,**values):
 return json.loads(command(action,runtime['compose']+['exec','-T','--user','33','app','php','/opt/module-target/control.php'],json.dumps(dict(runtime,action=action,**values)).encode()))

try:
 poc=Path(runtime['poc_path'])
 assert hashlib.sha256(poc.read_bytes()).hexdigest()=='2da894d6368ed3fdf37862c60bb3c6af83df7167e8b62085850fd510034f685c','Fetch the pinned independent PoC as documented'
 if runtime['phase']=='before':
  command('install',[sys.executable,str(here/'install.py'),sys.argv[1]])
  raw=command('seed',runtime['compose']+['exec','-T','--user','33','app','php','/opt/module-target/seed.php'],json.dumps(runtime).encode())
  seed=json.loads(next(line.split('=',1)[1]for line in raw.decode().splitlines()if line.startswith('OSTICKET_NATIVE_JSON=')))
  assert seed['account_confirmed']and seed['richtext']and seed['uid']==33
 else:seed=control('ticket')
 (out/'native-seed.json').write_text(json.dumps(seed,indent=2)+'\n')
 report['before']=control('state');assert report['before']['vendor_mismatches']==[]and report['before']['vendor_files']>=1400
 assert report['before']['version']=='v'+runtime['release']
 command('http-controls',[sys.executable,str(here/'http_controls.py'),sys.argv[1]])
 report['http']=json.loads((out/'http-controls.json').read_text());assert report['http']['passed']
 report['ticket_removal']=control('delete',ids=[seed['ticket_id']])
 report['after']=control('state');assert report['after']['vendor_mismatches']==[]
 assert seed['ticket_id']not in [v['ticket_id']for v in report['after']['tickets']]
 report['passed']=True
except BaseException as error:
 report['failure']={'type':type(error).__name__,'message':str(error)}
 raise
finally:save()
