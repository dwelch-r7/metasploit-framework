"""Genuine Craft asset upload, read and named transform prerequisites."""
from pathlib import Path
import base64
import hashlib
import importlib.util
import json
import struct
import subprocess
import sys
import urllib.parse

spec = importlib.util.spec_from_file_location('craft_native_shared', '/opt/module-target/native.py')
core = importlib.util.module_from_spec(spec)
spec.loader.exec_module(core)
STATE = Path('/tmp/module-target-craftasset-baseline.json')
DIRECTORY = Path('/app/web/module-target-assets')
INPUT = Path('/tmp/module-target-craftasset-input.png')
FILENAME = 'module-target-native-blue.png'
HANDLE = 'moduleTargetNative'
TRANSFORM = 'moduleTargetThumb'
CHECKS = []
COMMANDS = []


def check(name, passed):
    CHECKS.append({'name': name, 'passed': bool(passed)})
    if not passed:
        raise AssertionError(name)


def execute(arguments, data=None):
    result = subprocess.run(arguments, input=data, capture_output=True, timeout=20)
    COMMANDS.append({'argv': arguments, 'exit': result.returncode, 'stdout_base64': base64.b64encode(result.stdout).decode(), 'stderr': result.stderr.decode(errors='replace')})
    if result.returncode:
        raise RuntimeError('Native image operation failed: ' + result.stderr.decode(errors='replace'))
    return result.stdout


def csrf_form(body):
    inputs = core.Inputs()
    inputs.feed(body.decode())
    values = {key: value for key, value in inputs.values.items() if 'CSRF' in key}
    check('real-csrf-form', bool(values))
    return values


def administrator():
    client = core.opener()
    status, _, body = core.request('asset-login-form', '/admin/login', client=client)
    check('asset-login-form-status', status == 200)
    values = csrf_form(body)
    values.update(action='users/login', loginName='admin', password='module-target-craft-admin')
    status, _, body = core.request('asset-admin-login', data=values, client=client, headers={'Accept': 'application/json'})
    data = json.loads(body)
    check('asset-administrator-login', status == 200 and {'returnUrl', 'csrfTokenValue'}.issubset(data))
    return client, data['csrfTokenValue']


def local_url(url):
    parts = urllib.parse.urlsplit(url)
    check('asset-url-authority', parts.scheme == 'http' and parts.hostname == '127.0.0.1' and parts.port == 8080)
    return parts.path + ('?' + parts.query if parts.query else '')


def image(label, data, width, height):
    check(label + '-png-dimensions', data[:8] == b'\x89PNG\r\n\x1a\n' and struct.unpack('>II', data[16:24]) == (width, height))
    rgb = execute(['magick', '-', '-depth', '8', 'rgb:-'], data=data)
    check(label + '-blue-pixels', rgb == b'\x00\x00\xff' * width * height)


def metadata(asset_id):
    return core.application("$asset=\\craft\\elements\\Asset::findOne(['id'=>" + str(int(asset_id)) + "]);if(!$asset){throw new RuntimeException('Native asset not found');}echo json_encode(['id'=>$asset->id,'filename'=>$asset->getFilename(),'volumeId'=>$asset->getVolumeId(),'folderId'=>$asset->folderId,'width'=>$asset->width,'height'=>$asset->height,'url'=>$asset->getUrl(),'kind'=>$asset->kind]);")


def upload(client, csrf, folder_id, data):
    boundary = 'module-target-native-asset-boundary'
    check('multipart-boundary-not-in-image', boundary.encode() not in data)
    body = ('--' + boundary + '\r\nContent-Disposition: form-data; name="folderId"\r\n\r\n' + str(folder_id) + '\r\n').encode()
    body += ('--' + boundary + '\r\nContent-Disposition: form-data; name="assets-upload"; filename="' + FILENAME + '"\r\nContent-Type: image/png\r\n\r\n').encode() + data
    body += ('\r\n--' + boundary + '--\r\n').encode()
    status, _, response = core.request('native-asset-upload', '/index.php?p=actions/assets/upload', data=body, client=client, content_type='multipart/form-data; boundary=' + boundary, headers={'Accept': 'application/json', 'X-CSRF-Token': csrf})
    result = json.loads(response)
    check('genuine-asset-upload', status == 200 and result.get('filename') == FILENAME and isinstance(result.get('assetId'), int))
    return result['assetId']


def named_transform(asset_id, client=None, csrf=None):
    if client is None:
        client = core.opener()
        status, _, body = core.request('native-transform-csrf-form', '/admin/login', client=client)
        check('native-transform-form-status', status == 200)
        csrf = next(iter(csrf_form(body).values()))
    data = json.dumps({'assetId': asset_id, 'handle': TRANSFORM}).encode()
    status, _, body = core.request('native-named-transform', '/index.php?p=actions/assets/generate-transform', data=data, client=client, content_type='application/json', headers={'Accept': 'application/json', 'X-CSRF-Token': csrf})
    result = json.loads(body)
    check('native-named-transform-response', status == 200 and isinstance(result.get('url'), str))
    status, _, body = core.request('native-transformed-image-read', local_url(result['url']))
    check('native-transformed-image-status', status == 200)
    image('transformed-image', body, 6, 4)
    return {'url': result['url'], 'sha256': hashlib.sha256(body).hexdigest(), 'width': 6, 'height': 4}


def initialize():
    check('new-native-asset-paths', not any(path.exists() for path in [STATE, DIRECTORY, INPUT]))
    DIRECTORY.mkdir()
    fs = core.application("$fs=new \\craft\\fs\\Local(['name'=>'Module target native assets','handle'=>'" + HANDLE + "','hasUrls'=>true,'url'=>'http://127.0.0.1:8080/module-target-assets','path'=>'" + str(DIRECTORY) + "']);if(!$app->getFs()->saveFilesystem($fs)){throw new RuntimeException(json_encode($fs->getErrors()));}$app->getProjectConfig()->saveModifiedConfigData();echo json_encode(['handle'=>$fs->handle,'class'=>get_class($fs)]);")
    volume = core.application("$volume=new \\craft\\models\\Volume(['name'=>'Module target native assets','handle'=>'" + HANDLE + "','fsHandle'=>'" + HANDLE + "','transformFsHandle'=>'" + HANDLE + "','transformSubpath'=>'_transforms']);if(!$app->getVolumes()->saveVolume($volume)){throw new RuntimeException(json_encode($volume->getErrors()));}$app->getProjectConfig()->saveModifiedConfigData();$folder=$app->getAssets()->getRootFolderByVolumeId($volume->id);if(!$folder){throw new RuntimeException('Native root folder was not created');}echo json_encode(['id'=>$volume->id,'folderId'=>$folder->id,'handle'=>$volume->handle]);")
    transform = core.application("$transform=new \\craft\\models\\ImageTransform(['name'=>'Module target thumbnail','handle'=>'" + TRANSFORM + "','width'=>6,'height'=>4,'format'=>'png','mode'=>'crop']);if(!$app->getImageTransforms()->saveTransform($transform)){throw new RuntimeException(json_encode($transform->getErrors()));}$app->getProjectConfig()->saveModifiedConfigData();echo json_encode(['id'=>$transform->id,'handle'=>$transform->handle]);")
    loaded_fs = core.application("$fs=$app->getFs()->getFilesystemByHandle('" + HANDLE + "');echo json_encode(['class'=>$fs ? get_class($fs) : null,'handle'=>$fs ? $fs->handle : null]);")
    check('filesystem-persisted-across-application-processes', loaded_fs == {'class': 'craft\\fs\\Local', 'handle': HANDLE})
    execute(['magick', '-size', '12x8', 'xc:blue', str(INPUT)])
    try:
        source = INPUT.read_bytes()
        image('source-image', source, 12, 8)
        client, csrf = administrator()
        asset_id = upload(client, csrf, volume['folderId'], source)
        asset = metadata(asset_id)
        check('asset-persisted-metadata', asset['filename'] == FILENAME and asset['volumeId'] == volume['id'] and asset['folderId'] == volume['folderId'] and asset['width'] == 12 and asset['height'] == 8)
        persisted = DIRECTORY.joinpath(FILENAME).read_bytes()
        status, _, body = core.request('native-original-image-read', local_url(asset['url']))
        check('original-image-exact-read', status == 200 and body == persisted)
        image('uploaded-image', body, 12, 8)
        transformed = named_transform(asset_id, client, csrf)
        baseline = {'asset': asset, 'filesystem': fs, 'volume': volume, 'transform': transform, 'source_sha256': hashlib.sha256(source).hexdigest(), 'persisted_sha256': hashlib.sha256(persisted).hexdigest(), 'transformed': transformed}
        core_baseline = core.initialize()
        STATE.write_text(json.dumps(baseline, indent=2) + '\n')
        return {'initialized': True, 'baseline': baseline, 'core_baseline': core_baseline}
    finally:
        INPUT.unlink(missing_ok=True)


def audit():
    baseline = json.loads(STATE.read_text())
    native = core.audit()
    check('native-core-seventeen', native['passed'] and len(native['checks']) == 17)
    check('asset-metadata-preserved', metadata(baseline['asset']['id']) == baseline['asset'])
    persisted = DIRECTORY.joinpath(FILENAME).read_bytes()
    check('asset-source-preserved', hashlib.sha256(persisted).hexdigest() == baseline['persisted_sha256'])
    status, _, body = core.request('native-original-image-repeat', local_url(baseline['asset']['url']))
    check('original-image-repeat', status == 200 and body == persisted)
    image('repeat-image', body, 12, 8)
    transformed = named_transform(baseline['asset']['id'])
    check('named-transform-repeat', transformed == baseline['transformed'])
    return {'native_core': native, 'baseline': baseline, 'transformed': transformed}


def session_control():
    baseline = json.loads(STATE.read_text())
    spec = importlib.util.spec_from_file_location('craft_native_session', '/opt/module-target/native-session.py')
    session = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(session)
    record = session.control(core, baseline, Path('/opt/module-target/session-config.php').read_bytes())
    check('native-session-control', record['passed'])
    check('native-session-cleanup', all(record['cleanup'].values()) and record['existing_sessions_preserved'])
    check('asset-metadata-after-session-control', metadata(baseline['asset']['id']) == baseline['asset'])
    return record


if __name__ == '__main__':
    result = None
    try:
        operation = sys.argv[2]
        result = {'initialize': initialize, 'audit': audit, 'session': session_control}[operation]()
        print(json.dumps({'operation': operation, 'data': result, 'checks': CHECKS, 'http': core.HTTP, 'commands': COMMANDS, 'passed': all(check['passed'] for check in CHECKS)}))
    except Exception as error:
        diagnostic = Path('/tmp/module-target-native-session-control.json')
        session_record = json.loads(diagnostic.read_text()) if sys.argv[2] == 'session' and diagnostic.exists() else None
        print(json.dumps({'operation': sys.argv[2], 'data': result, 'checks': CHECKS, 'http': core.HTTP, 'commands': COMMANDS, 'session_control': session_record, 'error': {'type': type(error).__name__, 'message': str(error)}}))
        raise
