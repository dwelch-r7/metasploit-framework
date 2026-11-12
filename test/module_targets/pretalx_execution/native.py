"""Prove native exporter traversal and a benign, explicitly triggered hook."""
import datetime as dt
import hashlib
import io
import json
from pathlib import Path
import posixpath
import runpy
import site
import subprocess
import sys
import time
from urllib.parse import quote, unquote
import zipfile

import django

django.setup()
from django.conf import settings
from django.core.files.base import ContentFile
from django.utils._os import safe_join
from django_scopes import scopes_disabled
from pretalx import __version__
from pretalx.agenda.management.commands.export_schedule_html import get_export_path, get_export_zip_path
from pretalx.event.models import Event, Organiser
from pretalx.person.models import User
from pretalx.schedule.models import Room, TalkSlot
from pretalx.submission.models import Resource, Submission, SubmissionStates
import redis

sys.argv = ['native.py', 'state']
Browser = runpy.run_path('/lab/native.py')['Browser']
backend = redis.Redis(host='broker', db=1)
record = {'version': __version__, 'debug': settings.DEBUG,
          'bootstrap': json.loads(Path('/data/execution-bootstrap.json').read_text())}
probe = Path('/tmp/module-target-pretalx-elf')
subprocess.run(['cp', '/bin/true', str(probe)], check=True)
assert probe.read_bytes().startswith(b'\x7fELF')
process = subprocess.run([str(probe)], capture_output=True, timeout=5)
assert process.returncode == 0
record['native_elf_sha256'] = hashlib.sha256(probe.read_bytes()).hexdigest()
probe.unlink()
catalog = json.loads(Path('/lab/vendor.json').read_text())[__version__]['source_sha256']
record['source_hashes'] = {name: hashlib.sha256((Path('/pretalx/src/pretalx') / name).read_bytes()).hexdigest() for name in catalog}
assert record['source_hashes'] == catalog
marker = Path('/data/native-execution-marker')
marker.unlink(missing_ok=True)
user_site = Path(site.getusersitepackages())
ancestors = [user_site] + [p for p in user_site.parents if p != Path('/pretalx') and Path('/pretalx') in p.parents]
existing = {str(p): p.exists() for p in ancestors}
hook = None
tasks = []


def export(browser, event):
    before = set(backend.scan_iter('celery-task-meta-*'))
    zip_path = get_export_zip_path(event)
    zip_path.unlink(missing_ok=True)
    code, _ = browser.post(f'/orga/event/{event.slug}/schedule/export/trigger', f'/orga/event/{event.slug}/schedule/export/')
    assert code == 200
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        keys = set(backend.scan_iter('celery-task-meta-*')) - before
        if keys:
            assert len(keys) == 1
            result = json.loads(backend.get(next(iter(keys))))
            if result['status'] in ['SUCCESS', 'FAILURE']:
                tasks.append(result)
                return result, zip_path
        time.sleep(0.2)
    raise TimeoutError('The real export task did not reach a terminal result')


def normal_export(browser, event):
    task, zip_path = export(browser, event)
    assert task['status'] == 'SUCCESS', task
    code, data = browser.request(f'/orga/event/{event.slug}/schedule/export/download')
    assert code == 200
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        assert archive.testzip() is None
        assert f'{event.slug}/{event.slug}/index.html' in archive.namelist()
    return {'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest()}


try:
    with scopes_disabled():
        event = Event.objects.create(organiser=Organiser.objects.get(slug='validation'),
                                    name='Native execution control', slug='native-exec',
                                    date_from=dt.date(2030, 1, 10), date_to=dt.date(2030, 1, 10),
                                    timezone='UTC', locale_array='en', is_public=True)
        room = Room.objects.create(event=event, name='Native room')
        submission = Submission.objects.create(event=event, title='Native hook control',
                                               submission_type=event.cfp.default_type,
                                               abstract='Native startup-hook control', state=SubmissionStates.CONFIRMED)
        user = User.objects.get(email='organizer@example.invalid')
        submission.speakers.add(user)
        TalkSlot.objects.update_or_create(submission=submission, schedule=event.wip_schedule,
                                          defaults={'room': room, 'start': dt.datetime(2030, 1, 10, 9, tzinfo=dt.timezone.utc),
                                                    'end': dt.datetime(2030, 1, 10, 9, 30, tzinfo=dt.timezone.utc)})
        resource = Resource(submission=submission, description='Native benign startup resource')
        content = b"import pathlib; pathlib.Path('/data/native-execution-marker').write_text('native-startup-hook\\n')\n"
        resource.resource.save('native-hook.pth', ContentFile(content))
        event.release_schedule(name='native-control', user=user)

    browser = Browser()
    assert browser.login('organizer@example.invalid')[0] == 200
    assert browser.request('/orga/admin/')[0] == 200
    record['normal_before'] = normal_export(browser, event)
    resource_url = resource.resource.url
    export_tmp = get_export_path(event).with_name(event.slug + '-new')
    encoded_prefix = quote(posixpath.dirname(resource_url), safe='')
    climbs = len(export_tmp.parts) + 1
    encoded_tail = quote('../' * (len(user_site.parts) - 1), safe='').replace('.', '%2e') + quote(resource_url.lstrip('/'), safe='')
    uri = encoded_prefix + '/' + '../' * climbs + str(user_site).lstrip('/') + '/' + encoded_tail
    decoded = unquote(uri)
    assert decoded.startswith(settings.MEDIA_URL)
    served = Path(safe_join(settings.MEDIA_ROOT, posixpath.normpath(decoded[len(settings.MEDIA_URL):]).lstrip('/'))).resolve()
    assert served == Path(resource.resource.path).resolve(), (uri, served)
    hook = (export_tmp / uri).resolve()
    assert hook.parent == user_site and hook.name.endswith('.pth')
    assert not hook.exists() and len(hook.name.encode()) < 255
    record['uri'] = uri
    record['decoded_resource'] = str(served)
    record['hook'] = str(hook)
    with scopes_disabled():
        html = Resource(submission=submission, description='Native traversal resource')
        html.resource.save('native-traversal.html', ContentFile(f'<html><img src="{uri}"></html>'.encode()))

    task, _ = export(browser, event)
    exposed = __version__ == '2.3.1'
    assert (task['status'] == 'SUCCESS') == exposed, task
    assert hook.exists() == exposed
    assert not marker.exists(), 'An unrequested Python startup occurred'
    if exposed:
        data = hook.read_bytes()
        if settings.DEBUG:
            assert data == content, (data[:200], content)
        else:
            assert b'HTTP 404' in data and not any(line.startswith(b'import ') for line in data.splitlines())
        record['written_sha256'] = hashlib.sha256(data).hexdigest()
    else:
        assert 'Path traversal detected' in str(task['result'])

    process = subprocess.run([sys.executable, '-c', 'pass'], capture_output=True, text=True, timeout=10)
    record['trigger'] = {'argv': [sys.executable, '-c', 'pass'], 'exitstatus': process.returncode,
                         'stdout': process.stdout, 'stderr': process.stderr}
    assert process.returncode == 0 and not process.stderr
    assert marker.exists() == (exposed and settings.DEBUG)
    if marker.exists():
        assert marker.read_text() == 'native-startup-hook\n'
    record['executed'] = marker.exists()
    if hook.exists():
        hook.unlink()
    marker.unlink(missing_ok=True)
    for path in ancestors:
        if not existing[str(path)] and path.exists():
            path.rmdir()
    process = subprocess.run([sys.executable, '-c', 'pass'], capture_output=True, text=True, timeout=10)
    assert process.returncode == 0 and not process.stderr and not marker.exists()
    record['second_startup_clean'] = True
    with scopes_disabled():
        html.delete()
    record['normal_after'] = normal_export(browser, event)
    record['tasks'] = tasks
    record['history'] = browser.history
    Path('/data/native-execution.json').write_text(json.dumps(record, sort_keys=True))
    print(json.dumps(record, sort_keys=True))
finally:
    if hook and hook.exists():
        hook.unlink()
    marker.unlink(missing_ok=True)
