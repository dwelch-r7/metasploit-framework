"""Exercise installed motionEye and Motion independently of Framework output."""
from io import BytesIO
from pathlib import Path
import base64
import hashlib
import importlib.metadata
import json
import re
import shutil
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

from PIL import Image
import motioneye
from motioneye import utils


CONFIG = json.loads(Path(__file__).with_name('releases.json').read_text())
PROFILE = CONFIG['profiles'][sys.argv[1]]
RELEASE = CONFIG['releases'][PROFILE['release']]
CAMERA = CONFIG['camera']
MEDIA = Path('/var/lib/motioneye/module-target-native')
PROBE_MEDIA = Path('/var/lib/motioneye/module-target-native-probe')
PROOF = Path('/tmp/module-target-motioneye-native-proof')
PASSWORD = PROFILE['password']
HTTP = []


def request(path, data=None, username='admin', password=None, signed=True):
    method = 'POST' if data is not None else 'GET'
    body = json.dumps(data).encode() if data is not None else None
    if signed:
        path += '?' + urllib.parse.urlencode({'_username': username, '_': int(time.time() * 1000)})
        key = hashlib.sha1((PASSWORD if password is None else password).encode()).hexdigest()
        path += '&_signature=' + utils.compute_signature(method, path, body or b'', key)
    headers = {'Content-Type': 'application/json'} if body is not None else {}
    query = urllib.request.Request('http://127.0.0.1:8765' + path, data=body, headers=headers, method=method)
    try:
        response = urllib.request.urlopen(query, timeout=20)
    except urllib.error.HTTPError as error:
        response = error
    raw = response.read()
    HTTP.append({'path': path, 'method': method, 'request_base64': base64.b64encode(body or b'').decode(),
                 'code': response.code, 'body_base64': base64.b64encode(raw).decode()})
    try:
        value = json.loads(raw)
    except ValueError:
        value = raw.decode(errors='replace')
    return response.code, value


def poll(operation, seconds=20):
    deadline = time.monotonic() + seconds
    while True:
        result = operation()
        if result:
            return result
        if time.monotonic() >= deadline:
            raise TimeoutError('Native motionEye state did not settle within the bound')
        time.sleep(0.1)


def camera_config(identifier, directory):
    status, data = request('/config/' + str(identifier) + '/get/')
    assert status == 200 and data['id'] == identifier
    data.update({'name': 'Module target camera', 'enabled': True, 'text_overlay': False,
                 'motion_detection': False, 'still_images': True, 'capture_mode': 'manual',
                 'image_file_name': '%Y-%m-%d/%H-%M-%S', 'manual_snapshots': True,
                 'movies': False, 'root_directory': str(directory), 'framerate': 2})
    return data


def add_camera(directory):
    # Motion's documented legacy MJPEG decoder consumes the owned test card.
    # No web-application endpoint or method is replaced by this media source.
    existing_roots = {path.name for path in Path('/var/lib/motioneye').iterdir()}
    status, data = request('/config/add/', {'scheme': 'mjpeg', 'host': '127.0.0.1',
                                          'port': str(CAMERA['port']), 'path': CAMERA['path'],
                                          'username': '', 'password': '', 'proto': 'netcam'})
    assert status == 200 and isinstance(data.get('id'), int)
    identifier = data['id']
    config = camera_config(identifier, directory)
    assert request('/config/0/set/', {str(identifier): config}) == (200, {'reload': False, 'reboot': False, 'error': None})
    original = Path(data['root_directory'])
    if original.parent == directory.parent and original.name not in existing_roots and original.exists():
        assert original.is_dir() and not original.is_symlink()
        original.rmdir()  # Remove only the empty default directory from this add.
    return identifier


def frame_record(directory):
    path = directory / 'lastsnap.jpg'
    if not path.is_file():
        return None
    raw = path.read_bytes()
    if not raw:
        return None
    try:
        image = Image.open(BytesIO(raw)).convert('RGB')
    except OSError:
        return None  # Motion may still be replacing its acknowledged snapshot.
    width, height = image.size
    center, corner = image.getpixel((width // 2, height // 2)), image.getpixel((width // 8, height // 8))
    if not (center[0] > 180 and center[2] < 100 and corner[2] > 120 and corner[0] < 100):
        return None  # Reject Motion's empty/placeholder frames.
    return {'path': str(path), 'sha256': hashlib.sha256(raw).hexdigest(), 'size': image.size,
            'center': center, 'corner': corner, 'uid': path.stat().st_uid}


def snapshot_picture(identifier, directory):
    # Wait for the requested image, not a previously saved frame. Post another
    # action only after a fresh placeholder has actually been written.
    path = directory / 'lastsnap.jpg'
    stamp = path.stat().st_mtime_ns if path.is_file() else None
    assert request('/action/' + str(identifier) + '/snapshot/', {}) == (200, {})
    def attempt():
        nonlocal stamp
        if not path.is_file() or path.stat().st_mtime_ns == stamp:
            return None
        stamp = path.stat().st_mtime_ns
        record = frame_record(directory)
        if record:
            return record
        assert request('/action/' + str(identifier) + '/snapshot/', {}) == (200, {})
        return None
    return poll(attempt)


def empty_media(directory):
    if directory.exists():
        for path in directory.iterdir():
            if path.is_dir() and not path.is_symlink():
                shutil.rmtree(path)
            else:
                path.unlink()


def state():
    package = Path(motioneye.__file__).parent.parent
    sources = {name: hashlib.sha256((package / name).read_bytes()).hexdigest() for name in RELEASE['source_files']}
    processes = []
    for path in Path('/proc').iterdir():
        if not path.name.isdigit():
            continue
        try:
            command = (path / 'cmdline').read_bytes()
            if b'meyectl' in command and b'startserver' in command:
                processes.append({'pid': int(path.name),
                                  'starttime': (path / 'stat').read_text().rsplit(')', 1)[1].split()[19],
                                  'command_base64': base64.b64encode(command).decode()})
        except (FileNotFoundError, ProcessLookupError):
            continue
    config = {name: hashlib.sha256(Path('/etc/motioneye', name).read_bytes()).hexdigest()
              for name in ['motioneye.conf', 'motion.conf', 'camera-1.conf']}
    return {'source_files': sources, 'entrypoint_sha256': hashlib.sha256(Path('/entrypoint.sh').read_bytes()).hexdigest(),
            'server_processes': sorted(processes, key=lambda row: row['pid']), 'configuration': config,
            'native_media': sorted(str(path.relative_to(MEDIA)) for path in MEDIA.rglob('*')),
            'media_roots': sorted(path.name for path in Path('/var/lib/motioneye').iterdir()),
            'proof_exists': PROOF.exists(), 'camera_configurations': sorted(path.name for path in Path('/etc/motioneye').glob('camera-*.conf'))}


def initialize():
    marker = Path('/tmp/module-target-motioneye-initialized.json')
    assert not marker.exists()
    status, data = request('/config/0/get/', password='')
    assert status == 200 and data['admin_password'] == ''
    if PASSWORD:
        data['admin_password'] = PASSWORD
        status, response = request('/config/0/set/', {'main': data}, password='')
        assert status == 200 and response.get('error') is None
    assert request('/config/list/')[1]['cameras'] == []
    identifier = add_camera(MEDIA)
    assert identifier == 1
    frame = snapshot_picture(identifier, MEDIA)
    empty_media(MEDIA)
    marker.write_text(json.dumps({'profile': sys.argv[1]}))
    return {'profile': sys.argv[1], 'camera_id': identifier, 'frame': frame, 'http': HTTP, 'snapshot': state()}


def audit():
    checks = []
    def check(name, result):
        checks.append({'name': name, 'passed': bool(result)})
    before = state()
    check('installed-release-and-upstream-source', importlib.metadata.version('motioneye') == RELEASE['version']
          and before['source_files'] == RELEASE['source_files']
          and before['entrypoint_sha256'] == RELEASE['entrypoint_sha256'])
    check('original-web-processes-live', len(before['server_processes']) >= 1)
    check('native-camera-only-no-proof', before['camera_configurations'] == ['camera-1.conf'] and not before['proof_exists'])
    status, main = request('/config/0/get/')
    check('native-admin-authentication', status == 200 and main.get('admin_username') == 'admin'
          and main.get('admin_password') == ('*****' if PASSWORD else ''))
    check('wrong-password-denied', request('/config/0/get/', password='module-target-invalid')[0] == 403)
    check('absent-account-denied', request('/config/0/get/', username='module_target_absent')[0] == 403)
    check('normal-user-cannot-administer', request('/config/0/get/', username='user', password='')[0] == 403)
    check('unsigned-administration-denied', request('/config/0/get/', signed=False)[0] == 403)
    check('native-camera-list', [row['id'] for row in request('/config/list/')[1]['cameras']] == [1])
    frame = snapshot_picture(1, MEDIA)
    check('real-source-frame-not-placeholder', frame['uid'] == 0)
    empty_media(MEDIA)
    identifier = None
    try:
        identifier = add_camera(PROBE_MEDIA)
        check('independent-second-native-camera', identifier == 2)
        snapshot_picture(identifier, PROBE_MEDIA)
        camera_path = Path('/etc/motioneye/camera-' + str(identifier) + '.conf')
        camera_before = hashlib.sha256(camera_path.read_bytes()).hexdigest()
        config = camera_config(identifier, PROBE_MEDIA)
        config['image_file_name'] = '$(printf motioneye-native > ' + str(PROOF) + ').%Y-%m-%d-%H-%M-%S'
        status, response = request('/config/0/set/', {str(identifier): config})
        check('native-injection-write-or-rejection', status == (200 if PROFILE['release'] == 'vulnerable' else 500))
        camera_changed = hashlib.sha256(camera_path.read_bytes()).hexdigest() != camera_before
        check('native-configuration-write-or-preservation', camera_changed == (PROFILE['release'] == 'vulnerable'))
        assert request('/action/' + str(identifier) + '/snapshot/', {}) == (200, {})
        if PROFILE['release'] == 'vulnerable':
            poll(lambda: PROOF.exists())
            check('exact-native-command-proof', PROOF.read_bytes() == b'motioneye-native' and PROOF.stat().st_uid == 0)
        else:
            check('fixed-release-no-command-proof', not PROOF.exists())
    finally:
        if identifier is not None:
            check('native-probe-camera-removed', request('/config/' + str(identifier) + '/rem/', {}) == (200, {}))
        if PROOF.exists():
            PROOF.unlink()
        if PROBE_MEDIA.exists():
            shutil.rmtree(PROBE_MEDIA)
    after = state()
    check('original-source-process-config-state-preserved', before == after)
    return {'profile': sys.argv[1], 'version': RELEASE['version'], 'checks': checks, 'frame': frame,
            'http': HTTP, 'snapshot': after, 'passed': all(row['passed'] for row in checks)}


operation = sys.argv[2]
try:
    if operation == 'initialize':
        result = initialize()
    elif operation == 'snapshot':
        result = state()
    elif operation == 'audit':
        result = audit()
    elif operation == 'cleanup-media':
        paths = json.loads(sys.argv[3])
        result = []
        for name in paths:
            assert re.fullmatch(r'/var/lib/motioneye/[A-Za-z0-9]{4,16}', name)
            path = Path(name)
            existed = path.exists()
            if existed:
                assert path.is_dir() and not path.is_symlink()
                shutil.rmtree(path)
            result.append({'path': name, 'existed': existed, 'absent': not path.exists()})
    elif operation == 'tcp':
        port = int(sys.argv[3])
        rows = [line.split() for line in Path('/proc/net/tcp').read_text().splitlines()[1:]]
        result = [{'state': row[3], 'uid': int(row[7])} for row in rows if int(row[2].split(':')[1], 16) == port]
    else:
        raise ValueError('Unknown native operation')
    print(json.dumps(result))
    if isinstance(result, dict) and result.get('passed') is False:
        sys.exit(1)
except Exception as error:
    print(json.dumps({'profile': sys.argv[1], 'operation': operation, 'http': HTTP, 'checks': [], 'passed': False, 'error': {'type': type(error).__name__, 'message': str(error)}}))
    raise
