"""Provision the actual administrative permission used by the debug check."""
import json
from pathlib import Path
import pwd
import os
import site
import sys

import django

django.setup()
from django.conf import settings
from pretalx.person.models import User

user = User.objects.get(email='organizer@example.invalid')
user.is_staff = True
user.is_administrator = True
user.save(update_fields=['is_staff', 'is_administrator'])
home = pwd.getpwuid(os.getuid()).pw_dir
assert home == str(Path.home()) == '/pretalx'
assert site.ENABLE_USER_SITE
record = {'uid': os.getuid(), 'gid': os.getgid(), 'home': home,
          'python': sys.version, 'python_directory': 'python' + '.'.join(map(str, sys.version_info[:2])),
          'user_site': site.getusersitepackages(), 'user_site_enabled': site.ENABLE_USER_SITE,
          'debug': settings.DEBUG, 'administrator': user.is_administrator}
Path('/data/execution-bootstrap.json').write_text(json.dumps(record, sort_keys=True))
print(json.dumps(record), flush=True)
