"""Reuse the qualified native HTTP client and observe the genuine backend."""
import importlib.util
import base64
from http.cookies import SimpleCookie
import json
from pathlib import Path
import time
import uuid

source = Path(__file__).resolve().parents[1] / 'netalertx_file_read/native_probe.py'
specification = importlib.util.spec_from_file_location('netalertx_native_http', source)
http = importlib.util.module_from_spec(specification)
specification.loader.exec_module(http)
KEYS = ['DBCLNP_RUN', 'DBCLNP_CMD', 'DBCLNP_RUN_SCHD']


class ExecutionClient(http.NativeNetalertx):
    def __init__(self, runtime):
        self.runtime = runtime
        self.events = []
        self.commands = []
        self.states = []
        self.cookies = {}
        self.full_configuration = None

    def request(self, path, form=None, authenticated=False):
        # Internal-only labs publish no host port. This is actual loopback HTTP
        # in the application's network namespace, with redirects left visible.
        request = dict(path=path, form=form, cookies=self.cookies if authenticated else {})
        code = Path(__file__).with_name('transport.py').read_text()
        event = json.loads(self.command('python3', '-c', code, json.dumps(request)))
        if authenticated:
            for key, value in event['headers']:
                if key.lower() == 'set-cookie':
                    cookie = SimpleCookie(value)
                    self.cookies.update({name: item.value for name, item in cookie.items()})
        event.update(path=path, form=form, authenticated=authenticated, transport='Target namespace loopback HTTP')
        self.events.append(event)
        return dict(event, headers=dict(event['headers'])), base64.b64decode(event['body_base64']).decode('utf-8')

    def state(self):
        code = Path(__file__).with_name('state.py').read_text()
        result = json.loads(self.command('python3', '-c', code))
        self.states.append(dict(at=time.time(), state=result))
        return result

    def wait(self, predicate, timeout, label):
        deadline = time.monotonic() + timeout
        while True:
            value = self.state()
            if predicate(value):
                return value
            if time.monotonic() >= deadline:
                raise TimeoutError(label)
            time.sleep(1.5)

    def settings(self, values, authenticated=False):
        if self.full_configuration is None:
            self.full_configuration = self.state()['all_configuration']
        preserved = dict(self.full_configuration, **values)
        entries = []
        for key, value in preserved.items():
            if isinstance(value, bool):
                kind = 'boolean'
            elif isinstance(value, int):
                kind = 'integer'
            elif isinstance(value, str):
                kind = 'string'
            else:
                kind, value = 'json', repr(value)
            entries.append(['Preserved', key, kind, value])
        return self.request('/php/server/util.php', {'function': 'savesettings', 'settings': json.dumps(entries)}, authenticated)[0]

    def enqueue(self, action, authenticated=False):
        return self.request('/php/server/util.php', {'function': 'addToExecutionQueue', 'action': str(uuid.uuid4()) + '|' + action}, authenticated)[0]

    def assert_environment(self, state):
        assert not state['api_error'] and state['backend']
        assert state['configuration']['SCAN_SUBNETS'] == []
        assert set(state['plugins']) == {'DBCLNP', 'NEWDEV', 'NTFPRCS', 'SETPWD', 'UI', 'WORKFLOWS'}, state['plugins']
        for key, value in state['configuration'].items():
            if key.endswith('_RUN') and key != 'DBCLNP_RUN':
                assert value == 'disabled', (key, value)
        assert state['cgroups']['memory.events']['oom'] == '0'
        assert state['cgroups']['memory.events']['oom_kill'] == '0'
        assert state['cgroups']['pids.events']['max'] == '0'

    def write(self, artifacts, proof):
        Path(artifacts).joinpath('native-execution.json').write_text(json.dumps(dict(proof=proof, requests=self.events, commands=self.commands, states=self.states), indent=2) + '\n')
