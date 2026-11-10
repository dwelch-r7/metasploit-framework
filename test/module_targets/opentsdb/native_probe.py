"""Real vendor/query/auth/command/ELF controls; no Framework module invocation."""
import hashlib
import itertools
import json
import os
import pathlib
import shlex
import urllib.parse
from client import OpenTsdbTarget

ROOT = pathlib.Path(__file__).resolve().parent
QUERY = {'start': '2023/11/14-22:13:19', 'end': '2023/11/14-22:13:22', 'm': 'sum:sys.cpu.user'}
AUTH = ('module-test-user', 'module-test-password')
VALUES = {'simple': 'Module target exact bytes', 'quotes': 'single\' and "double" quotes',
          'backslash': r'backslash\tpath\\tail', 'plus': 'literal + >>> $HOME; spaces',
          'chmod': 'literal chmod +x; echo end'}


def main():
    runtime = json.loads(pathlib.Path(os.environ['MODULE_TARGET_RUNTIME']).read_text())
    profile = os.environ['OPENTSDB_PROFILE']
    release = {'yrange': '240', 'yrange_fixed': '241', 'key': '241', 'key_fixed': '250'}[profile]
    provenance = json.loads((ROOT / 'provenance.json').read_text())[release]
    api = OpenTsdbTarget(runtime)
    artifacts = pathlib.Path(runtime['artifacts'])
    proof = {'profile': profile, 'release': release, 'identity': {}, 'native_commands': []}
    for label, args in [('uid', ['id']), ('processes', ['ps', '-eo', 'user,pid,ppid,args']),
                        ('java', ['java', '-version']), ('gnuplot', ['gnuplot', '--version']),
                        ('version', ['/usr/share/opentsdb/bin/tsdb', 'version']),
                        ('hbase', ['/opt/hbase/bin/hbase', 'version'])]:
        proof['identity'][label] = api.command('affected', *args)
    assert proof['identity']['uid']['stdout'] == 'uid=0(root) gid=0(root) groups=0(root)\n'
    assert provenance['version'] in proof['identity']['version']['stdout']
    actual = {}
    row = api.command('affected', '/bin/sh', '-c', "find /usr/share/opentsdb -type f -name '*.jar' -exec sha256sum {} +")
    for line in row['stdout'].splitlines():
        digest, path = line.split(None, 1)
        actual[path] = digest
    if release == '250':
        revision = api.command('affected', 'cat', '/usr/local/share/module-target-provenance/opentsdb-revision.txt')['stdout'].strip()
        assert revision == provenance['revision']
        manifest = api.command('affected', 'cat', '/usr/local/share/module-target-provenance/opentsdb-jars.sha256')['stdout']
        expected = {path.removeprefix('/stage'): digest for digest, path in (line.split(None, 1) for line in manifest.splitlines())}
    else:
        expected = provenance['jars']
    assert actual == expected, (actual, expected)
    proof['runtime_jars'] = actual
    row, _ = api.get('affected', '/')
    assert row['code'] == 200 and '<title>OpenTSDB' in row['body']
    row, _ = api.get('affected', '/api/version')
    document = json.loads(row['body'])
    assert row['code'] == 200 and document['version'] == provenance['version']
    assert document['full_revision'] == provenance['revision'], document
    proof['version'] = document
    points = [{'metric': metric, 'timestamp': 1700000000 + offset, 'value': 12.5 + offset,
               'tags': {'host': 'module-target'}} for metric in ['sys.cpu.user', 'sys.cpu.nice', 'sys.cpu.idle'] for offset in [0, 1]]
    row, _ = api.request('affected', '/api/put?sync&details', method='POST', document=points)
    assert row['code'] == 200 and json.loads(row['body']) == {'success': 6, 'failed': 0, 'errors': []}, row
    metrics = json.loads(api.get('affected', '/suggest', {'type': 'metrics'})[0]['body'])
    aggregators = json.loads(api.get('affected', '/aggregators')[0]['body'])
    assert sorted(metrics) == ['sys.cpu.idle', 'sys.cpu.nice', 'sys.cpu.user']
    assert len(aggregators) == 35 and len(set(aggregators)) == 35
    # Every choice available to the modules must have real data and accept a graph query.
    for metric, aggregator in itertools.product(metrics, aggregators):
        row, _ = api.get('affected', '/api/query', dict(QUERY, m=aggregator + ':' + metric))
        data = json.loads(row['body'])
        assert row['code'] == 200 and len(data) == 1 and len(data[0]['dps']) == 2, row
    row, body = api.get('affected', '/q', dict(QUERY, png=''))
    assert row['code'] == 200 and body.startswith(b'\x89PNG\r\n\x1a\n') and len(body) > 1000
    (artifacts / 'native-opentsdb-benign.png').write_bytes(body)
    for auth, code in [(None, 401), (('module-test-user', 'incorrect-password'), 401), (AUTH, 200)]:
        assert api.get('gateway', '/tsdb/api/version', auth=auth)[0]['code'] == code
    for path in ['/module-target-missing/', '/module-target-missing/api/version']:
        assert api.get('affected', path)[0]['code'] == 404
    row, _ = api.get('unrelated', '/')
    assert row['code'] == 200 and 'OpenTSDB' not in row['body']
    tools = ['curl', 'wget', 'which', 'bash', 'base64', 'printf', 'chmod', 'rm', 'stat', 'perl']
    api.command('affected', '/bin/bash', '-c', 'for tool in "$@"; do command -v "$tool" || exit 1; done', 'module-target', *tools)
    # Compile transparent no-op ELF files in the canonical Framework image, then
    # execute on the target: host architecture alone is not an x86 execution gate.
    for arch in [32, 64]:
        source = '/usr/src/metasploit-framework/test/module_targets/opentsdb/native_exit.asm'
        binary = artifacts / ('native-opentsdb-exit-' + str(arch))
        api.command('framework', 'nasm', '-f', 'bin', '-DARCH=' + str(arch), source, '-o', str(binary))
        data = binary.read_bytes()
        assert data[:5] == b'\x7fELF' + bytes([1 if arch == 32 else 2])
        destination = '/tmp/module-target-opentsdb-native-elf-' + str(arch)
        api.command('affected', 'test', '-e', destination, expected=1)
        api.command('affected', '/bin/sh', '-c', 'cat > "$1"; chmod 700 "$1"', 'module-target', destination, input_data=data)
        digest = api.command('affected', 'sha256sum', destination)['stdout'].split()[0]
        assert digest == hashlib.sha256(data).hexdigest()
        api.command('affected', destination, expected=42)
        api.command('affected', 'rm', '--', destination)
        api.command('affected', 'test', '-e', destination, expected=1)
    family = profile.split('_')[0]
    vulnerable = not profile.endswith('_fixed')
    for label, value in VALUES.items():
        path = '/tmp/module-target-opentsdb-native-' + label
        command = 'printf %s ' + shlex.quote(value) + ' > ' + path
        api.command('affected', 'test', '-e', path, expected=1)
        api.command('affected', '/bin/sh', '-c', command)
        assert api.command('affected', 'cat', path)['stdout'] == value
        api.command('affected', 'rm', '--', path)
        params = dict(QUERY, wxh='800x400', json='')
        literal = json.dumps(command, ensure_ascii=False)
        parameter = 'yrange' if family == 'yrange' else 'key'
        expression = '[1:system(' + literal + ')]' if family == 'yrange' else ';system ' + literal + ';#'
        # GraphHandler.popParam in the genuine 2.4.1/fixed trees explicitly
        # URL-decodes the already parsed value again; 2.4.0 does not. Preserve
        # literal percent/plus bytes through that actual extra decode.
        params[parameter] = expression if release == '240' else urllib.parse.quote(expression, safe='')
        row, _ = api.get('affected', '/q', params)
        if vulnerable:
            assert api.command('affected', 'cat', path)['stdout'] == value, row
            assert api.command('affected', 'stat', '-c', '%u:%g', path)['stdout'] == '0:0\n'
            api.command('affected', 'rm', '--', path)
        else:
            assert row['code'] == 400, row
            refusal = json.loads(row['body']).get('err', '')
            if family == 'yrange':
                assert "'yrange' was invalid" in refusal, row
            else:
                assert 'illegal character' in refusal.lower() and 'key' in refusal.lower(), row
            assert 'URLDecoder' not in refusal, row
        api.command('affected', 'test', '-e', path, expected=1)
        proof['native_commands'].append({'case': label, 'command': command, 'expected': value,
                                         'executed': vulnerable, 'http_code': row['code'], 'removed': True})
    proof.update(graph_parameter_decodes=1 if release == '240' else 2, status='passed', cli=len(api.commands), http=len(api.requests), metrics=metrics, aggregators=aggregators)
    print(json.dumps(proof))


if __name__ == '__main__':
    main()
