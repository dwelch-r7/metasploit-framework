from pathlib import Path
import json,sys
from native_http import Client

def main():
 runtime=json.loads(Path(sys.argv[1]).read_text());out=Path(runtime['directory']);report={'owner_loaded':False,'requests':[],'phase':'installer'}
 def save():(out/'http-setup.json').write_text(json.dumps(report,indent=2)+'\n')
 try:
  client=Client('installer',runtime,report,save);status,body=client.request('form','/setup/install.php');assert status==200
  values={'s':'install','name':'Module Target Helpdesk','email':'support@example.test','fname':'Module','lname':'Target','admin_email':'module-admin@example.test','username':'module_admin','passwd':runtime['password'],'passwd2':runtime['password'],'prefix':'ost_','dbhost':'db','dbname':'osticket','dbuser':'module_target','dbpass':'module-target-db-password','lang_id':'en_US','timezone':'UTC'}
  status,body=client.request('install','/setup/install.php',values);assert status==200 and b'Congratulations' in body,(status,body[-1000:]);report['installer_passed']=True
 except BaseException as error:report['failure']={'type':type(error).__name__,'message':str(error)};raise
 finally:save()
if __name__=='__main__':main()
