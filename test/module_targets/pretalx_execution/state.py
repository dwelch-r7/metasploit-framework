"""Record and explicitly neutralize only this disposable event's write vectors."""
import hashlib
import json
from pathlib import Path
import sys

import django

django.setup()
from django_scopes import scopes_disabled
from pretalx.event.models import Event
import redis

mode = sys.argv[1]
with scopes_disabled():
    event = Event.objects.get(slug='validation')
    rows = list(event.submissions.values('code', 'title', 'description', 'state'))
    vectors = [row for row in rows if '<img' in (row['description'] or '') and '%2fmedia' in row['description'].lower()]
    restored = []
    if mode == 'restore':
        for row in vectors:
            event.submissions.filter(code=row['code']).update(description='')
            restored.append({'code': row['code'], 'description_sha256': hashlib.sha256(row['description'].encode()).hexdigest()})
        redis.Redis(host='broker', db=2).flushdb()
    data = {'mode': mode, 'vectors': vectors, 'restored': restored, 'submissions': rows,
            'bootstrap': json.loads(Path('/data/execution-bootstrap.json').read_text()),
            'queue': redis.Redis(host='broker', db=0).llen('celery')}
print(json.dumps(data, sort_keys=True))
