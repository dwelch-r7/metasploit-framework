"""Create a disposable conference through the application's native models."""
import datetime as dt
import hashlib
import json
from pathlib import Path

import django

django.setup()
from django_scopes import scopes_disabled
from pretalx import __version__
from pretalx.event.models import Event, Organiser, Team
from pretalx.person.models import User
from pretalx.schedule.models import Availability, Room

ROOT = Path('/data/proof')
ROOT.mkdir(exist_ok=True)
for name, content in {
    'proof.txt': b'Pretalx exact file proof\n<node>& "quoted"\nsecond line\n',
    'space name.txt': b'Pretalx space file\n',
    'empty.txt': b'',
}.items():
    (ROOT / name).write_bytes(content)

with scopes_disabled():
    if not Event.objects.exists():
        organiser = Organiser.objects.create(name='Container validation', slug='validation')
        user = User.objects.create_user(email='organizer@example.invalid', name='Lab Organizer', password='module-target-pretalx-password')
        User.objects.create_user(email='speaker@example.invalid', name='Lab Speaker', password='module-target-pretalx-password')
        event = Event.objects.create(
            organiser=organiser, name='Module target conference', slug='validation',
            date_from=dt.date(2030, 1, 10), date_to=dt.date(2030, 1, 10),
            timezone='UTC', locale_array='en', is_public=True,
        )
        team = Team.objects.create(organiser=organiser, name='Organizers', all_events=True,
                                  can_change_event_settings=True, can_change_submissions=True)
        team.members.add(user)
        room = Room.objects.create(event=event, name='Main room')
        Availability.objects.create(event=event, room=room,
                                    start=dt.datetime(2030, 1, 10, 9, tzinfo=dt.timezone.utc),
                                    end=dt.datetime(2030, 1, 10, 17, tzinfo=dt.timezone.utc))
        event.cfp.default_type.default_duration = 30
        event.cfp.default_type.save()
    event = Event.objects.get(slug='validation')
    evidence = {'version': __version__, 'event': event.slug, 'public': event.is_public,
                'rooms': event.rooms.count(), 'users': User.objects.count(),
                'proofs': {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in ROOT.iterdir()}}
Path('/data/bootstrap.json').write_text(json.dumps(evidence, sort_keys=True))
print(json.dumps(evidence), flush=True)
