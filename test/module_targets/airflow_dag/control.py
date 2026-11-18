from pathlib import Path
import hashlib,json,os,socket,shutil,sys
import airflow
from airflow import models,settings
from airflow.configuration import conf
from airflow.contrib.auth.backends.password_auth import PasswordUser
from airflow.jobs.base_job import BaseJob
config=json.loads(Path('/opt/module-target/profiles.json').read_text());session=settings.Session()
def value(item):return item.isoformat()if hasattr(item,'isoformat')else item
def rows(items,fields):return[{field:value(getattr(item,field))for field in fields}for item in items]
try:
 if len(sys.argv)>1:
  assert sys.argv[1]=='reset'
  requested=json.loads(sys.argv[2]);assert set(requested)=={'runs','paused'}and isinstance(requested['paused'],bool)
  for expected in requested['runs']:
   run=session.query(models.DagRun).filter_by(id=expected['id']).one()
   actual=rows([run],['id','dag_id','run_id','execution_date','state','external_trigger','conf'])[0]
   assert actual==expected and run.dag_id==config['dag_id']and run.state in ['success','failed']
   # Remove only the exact terminal runs observed by the caller. Other DAGs,
   # scheduler history and unmatched execution dates stay intact.
   for model_name in ['XCom','TaskInstance','TaskFail','TaskReschedule','Log']:
    model=getattr(models,model_name,None)
    if model is not None:
     session.query(model).filter(model.dag_id==run.dag_id,model.execution_date==run.execution_date).delete(synchronize_session=False)
   for task_id in ['run_this',config['task_id']]:
    logs=Path(conf.get('core','base_log_folder'))/run.dag_id/task_id/run.execution_date.isoformat()
    if logs.exists():
     assert logs.is_dir()and not logs.is_symlink()
     shutil.rmtree(str(logs))
   session.delete(run)
  dag=session.query(models.DagModel).filter_by(dag_id=config['dag_id']).first()
  if dag:dag.is_paused=requested['paused']
  session.commit()
 users=rows(session.query(PasswordUser).order_by(PasswordUser.id).all(),['id','username','email','superuser','password'])
 dags=rows(session.query(models.DagModel).order_by(models.DagModel.dag_id).all(),['dag_id','is_paused','is_active','fileloc'])
 runs=rows(session.query(models.DagRun).order_by(models.DagRun.execution_date).all(),['id','dag_id','run_id','execution_date','state','external_trigger','conf'])
 tasks=rows(session.query(models.TaskInstance).order_by(models.TaskInstance.execution_date,models.TaskInstance.task_id).all(),['dag_id','task_id','execution_date','state','pid','hostname','try_number','start_date','end_date'])
 jobs=rows(session.query(BaseJob).filter(BaseJob.job_type=='SchedulerJob').order_by(BaseJob.id).all(),['id','job_type','state','latest_heartbeat','hostname'])
 deployment=json.loads(Path('/opt/airflow/module-target-deployment.json').read_text())
 result={'version':airflow.__version__,'uid':os.getuid(),'hostname':socket.gethostname(),'deployment':deployment,'users':users,'dags':dags,'runs':runs,'tasks':tasks,'scheduler_jobs':jobs,'configuration':{section+'.'+key:conf.get(section,key)for section,key in [('core','executor'),('core','load_examples'),('core','dags_folder'),('webserver','authenticate'),('webserver','auth_backend'),('webserver','base_url'),('api','auth_backend')]}}
 print('CONTROL_JSON='+json.dumps(result))
finally:session.close()
