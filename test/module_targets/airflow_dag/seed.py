from pathlib import Path
import json
from airflow import models,settings
from airflow.contrib.auth.backends.password_auth import PasswordUser
config=json.loads(Path('/opt/module-target/profiles.json').read_text())
session=settings.Session()
try:
 assert session.query(models.User).count()==0
 user=PasswordUser(models.User());user.username=config['username'];user.email=config['email'];user.superuser=True;user.password=config['password'];session.add(user);session.commit()
 assert user.authenticate(config['password'])and not user.authenticate('Module-wrong-password42!')
 print('SEED_JSON='+json.dumps({'id':user.id,'username':user.username,'superuser':user.superuser,'password_hash':user.password}))
finally:session.close()
