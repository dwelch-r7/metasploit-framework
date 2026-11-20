import importlib.util, json, runpy, sys
from pathlib import Path
runtime_path, component, operation, *arguments = sys.argv[1:]
if component == 'host_port':
    runpy.run_path('test/module_targets/kong_gateway/controls.py', run_name='__main__')
    raise SystemExit('Host probe did not exit')
if component not in ['network.py', 'state_probe.py']:
    raise ValueError('Unknown SDK control')
sys.argv = [sys.argv[0], runtime_path, operation, *arguments]
spec = importlib.util.spec_from_file_location('native', Path(__file__).with_name('native.py'))
backend = importlib.util.module_from_spec(spec)
sys.modules['native'] = backend
spec.loader.exec_module(backend)
state = json.loads(backend.state_path.read_text())
backend.expected_uid = state['uid']
backend.execution_user = state['uid']
sys.argv = [sys.argv[0], runtime_path, state['version'], operation, *arguments]
if component == 'network.py' and operation == 'callback':
    runpy.run_path(str(Path(__file__).with_name('network.py')), run_name='__main__')
    raise SystemExit(0)
runpy.run_path(str(Path('test/module_targets/kafka_ui') / component), run_name='__main__')
