"""Inspect retained genuine request bytes without extracting or executing them."""
import base64
import hashlib
import io
import json
from pathlib import Path
import sys
import zipfile

body = Path(sys.argv[1]).read_bytes()
with zipfile.ZipFile(io.BytesIO(body)) as archive:
    assert archive.testzip() is None
    names = sorted(archive.namelist())
    config = archive.read('metasploit.dat')
    manifest = archive.read('META-INF/MANIFEST.MF')
    payload_class = archive.read('metasploit/Payload.class')
print(json.dumps(dict(bytes=len(body), sha256=hashlib.sha256(body).hexdigest(), names=names,
                      config_base64=base64.b64encode(config).decode(),
                      manifest_base64=base64.b64encode(manifest).decode(),
                      payload_class_sha256=hashlib.sha256(payload_class).hexdigest())))
