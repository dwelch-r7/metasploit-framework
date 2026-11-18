from pathlib import Path
import hashlib,json,os,shutil
import airflow
from airflow.configuration import conf
config=json.loads(Path('/opt/module-target/profiles.json').read_text())
folder=Path(conf.get('core','dags_folder'));folder.mkdir(parents=True,exist_ok=True)
source=Path(airflow.__file__).parent/'example_dags/example_trigger_target_dag.py'
original=hashlib.sha256(source.read_bytes()).hexdigest()
assert original==config['versions'][airflow.__version__]
mode=os.environ.get('MODULE_TARGET_MODE','vulnerable')
assert mode in ['vulnerable','fixed','denied','missing','patched','prefix','no_scheduler']
if mode=='patched':source=Path('/opt/module-target/fixed-example.py')
if mode!='missing':shutil.copyfile(str(source),str(folder/'example_trigger_target_dag.py'))
report={'version':airflow.__version__,'mode':mode,'uid':os.getuid(),'original_dag_sha256':original,'deployed_dag_sha256':hashlib.sha256(source.read_bytes()).hexdigest()if mode!='missing'else None,'dags_folder':str(folder)}
assert report['uid']==config['uid']
Path('/opt/airflow/module-target-deployment.json').write_text(json.dumps(report,indent=2)+'\n')
print('DEPLOY_JSON='+json.dumps(report))
