from pathlib import Path
import base64
import glob
import hashlib
import json
import sys
import zipfile

profile = Path(sys.argv[1])
result = {'profile': str(profile), 'files': {}, 'sources': {}}
for name in ['handlers.json', 'user.js', 'prefs.js']:
    path = profile / name
    if path.is_file():
        raw = path.read_bytes()
        result['files'][name] = {'base64': base64.b64encode(raw).decode(), 'sha256': hashlib.sha256(raw).hexdigest()}
assert 'handlers.json' in result['files']
for filename in glob.glob('/opt/firefox*/**/omni.ja', recursive=True) + glob.glob('/usr/lib/firefox*/**/omni.ja', recursive=True):
    try:
        with zipfile.ZipFile(filename) as archive:
            for name in archive.namelist():
                if name.endswith(('HandlerService.sys.mjs', 'HelperAppDlg.sys.mjs', 'greprefs.js')):
                    raw = archive.read(name)
                    result['sources'][filename + ':' + name] = {'base64': base64.b64encode(raw).decode(), 'sha256': hashlib.sha256(raw).hexdigest()}
    except zipfile.BadZipFile as error:
        path = Path(filename)
        result['sources'][filename] = {'reader_error': type(error).__name__, 'message': str(error), 'bytes': path.stat().st_size, 'sha256': hashlib.sha256(path.read_bytes()).hexdigest(), 'note': 'Optional optimized-archive source capture unavailable; profile and native behavior remain authoritative.'}
print(json.dumps(result))
