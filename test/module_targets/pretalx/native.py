"""Independent native ORM preparation and real HTTP/worker/ZIP controls."""
import datetime as dt
import hashlib
import http.cookiejar
import io
import json
from pathlib import Path
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile

import django
django.setup()
from bs4 import BeautifulSoup
from django.conf import settings
from django.core.files.base import ContentFile
from django_scopes import scopes_disabled
from pretalx import __version__
from pretalx.event.models import Event, Organiser
from pretalx.person.models import User
from pretalx.schedule.models import Availability, Room, TalkSlot
from pretalx.submission.models import Resource, Submission, SubmissionStates
from pretalx.agenda.management.commands.export_schedule_html import get_export_zip_path
import redis

BASE = 'http://target:8000'
PASSWORD = 'module-target-pretalx-password'
PROOF = b'Pretalx exact file proof\n<node>& "quoted"\nsecond line\n'


class Browser:
    def __init__(self):
        self.cookies = http.cookiejar.CookieJar()
        self.client = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(self.cookies))
        self.history = []

    def request(self, path, values=None):
        data = urllib.parse.urlencode(values).encode() if values is not None else None
        request = urllib.request.Request(BASE + path, data=data)
        try:
            response = self.client.open(request, timeout=30)
        except urllib.error.HTTPError as error:
            response = error
        body = response.read()
        self.history.append({'path': path, 'post': values is not None, 'status': response.code,
                             'final': urllib.parse.urlsplit(response.url).path,
                             'sha256': hashlib.sha256(body).hexdigest(), 'bytes': len(body)})
        return response.code, body

    def post(self, path, token_page):
        code, body = self.request(token_page)
        assert code == 200, self.history
        token = BeautifulSoup(body, 'lxml').select_one('input[name=csrfmiddlewaretoken]')['value']
        return self.request(path, {'csrfmiddlewaretoken': token})

    def login(self, email, password=PASSWORD):
        code, body = self.request('/orga/login/')
        assert code == 200
        token = BeautifulSoup(body, 'lxml').select_one('input[name=csrfmiddlewaretoken]')['value']
        return self.request('/orga/login/', {'csrfmiddlewaretoken': token, 'login_email': email,
                                              'login_password': password})


def native():
    """Use a separate conference; neither call nor copy the owning module."""
    catalog = Path('/lab/vendor.json')
    source_hashes = {}
    if catalog.exists():
        expected = json.loads(catalog.read_text())[__version__]['source_sha256']
        source_hashes = {name: hashlib.sha256((Path('/pretalx/src/pretalx') / name).read_bytes()).hexdigest()
                         for name in expected}
        assert source_hashes == expected
    with scopes_disabled():
        event, _ = Event.objects.get_or_create(slug='native', defaults={
            'organiser': Organiser.objects.get(slug='validation'), 'name': 'Native export control',
            'date_from': dt.date(2030, 1, 10), 'date_to': dt.date(2030, 1, 10),
            'timezone': 'UTC', 'locale_array': 'en', 'is_public': True})
        room, _ = Room.objects.get_or_create(event=event, name='Native room')
        submission = Submission.objects.create(event=event, title='Native scheduled proof',
                                               submission_type=event.cfp.default_type,
                                               abstract='<img src="/media///data/proof/proof.txt"/>',
                                               state=SubmissionStates.CONFIRMED)
        user = User.objects.get(email='organizer@example.invalid')
        submission.speakers.add(user)
        resource = Resource(submission=submission, description='Native HTML read control')
        resource.resource.save('native-proof.html', ContentFile(b'<html><img src="/media///data/proof/proof.txt"></html>'))
        TalkSlot.objects.update_or_create(submission=submission, schedule=event.wip_schedule,
                                          defaults={'room': room, 'start': dt.datetime(2030, 1, 10, 9, tzinfo=dt.timezone.utc),
                                                    'end': dt.datetime(2030, 1, 10, 9, 30, tzinfo=dt.timezone.utc)})
        zip_path = get_export_zip_path(event)
        if zip_path.exists():
            zip_path.unlink()
        event.release_schedule(name='native-control-' + str(event.schedules.count()), user=user)
        assert not zip_path.exists()

    wrong = Browser()
    assert wrong.login('organizer@example.invalid', 'wrong-password')[0] == 200
    assert wrong.history[-1]['final'] == '/orga/login/'
    speaker = Browser()
    assert speaker.login('speaker@example.invalid')[0] == 200
    assert speaker.request('/orga/event/native/schedule/export/')[0] == 404
    organizer = Browser()
    assert organizer.login('organizer@example.invalid')[0] == 200
    assert organizer.history[-1]['final'] == '/orga/event/'
    assert organizer.post('/orga/event/native/schedule/export/trigger', '/orga/event/native/schedule/export/')[0] == 200
    deadline = time.monotonic() + 90
    while True:
        try:
            with zipfile.ZipFile(zip_path) as current:
                if current.testzip() is None:
                    break
        except (FileNotFoundError, zipfile.BadZipFile):
            pass
        if time.monotonic() >= deadline:
            raise TimeoutError('Real Celery export did not create the native ZIP')
        time.sleep(0.2)
    code, data = organizer.request('/orga/event/native/schedule/export/download')
    assert code == 200
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        names = archive.namelist()
        assert 'native/native/index.html' in names
        proof = 'native/media/data/proof/proof.txt'
        exposed = proof in names and archive.read(proof) == PROOF
        assert exposed == (__version__ == '2.3.1'), (names, exposed)
    return {'version': __version__, 'debug': settings.DEBUG, 'sqlite': settings.DATABASES['default']['ENGINE'],
            'celery': settings.HAS_CELERY, 'zip_bytes': len(data), 'zip_sha256': hashlib.sha256(data).hexdigest(),
            'zip_names': names, 'exposed': exposed, 'source_hashes': source_hashes, 'organizer': organizer.history,
            'speaker': speaker.history, 'wrong': wrong.history}


def state():
    with scopes_disabled():
        event = Event.objects.get(slug='validation')
        value = {'version': __version__, 'submissions': list(event.submissions.values('code', 'title', 'state', 'abstract')),
                 'schedules': list(event.schedules.values('version', 'published')),
                 'rooms': event.rooms.count(), 'availabilities': event.availabilities.count()}
    value['queue'] = redis.Redis(host='broker', db=0).llen('celery')
    return value


mode = sys.argv[1]
print(json.dumps(native() if mode == 'native' else state(), default=str, sort_keys=True))
