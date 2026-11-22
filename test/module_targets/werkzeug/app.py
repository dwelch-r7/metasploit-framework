"""Small WSGI application wrapped by the unmodified installed debugger."""
from pathlib import Path
import getpass
import importlib.metadata
import json
import os
import sys
import uuid
from werkzeug.debug import DebuggedApplication
from werkzeug.serving import run_simple
from werkzeug.wrappers import Request, Response


class LabApplication:
    def __call__(self, environ, start_response):
        request = Request(environ)
        if request.path == '/health':
            response = Response('module-target-werkzeug-ready\n', mimetype='text/plain')
        elif request.path == '/trigger':
            value = request.form.get('file') if request.method in ['POST', 'PUT', 'PATCH'] else request.args.get('file')
            if value == 'raise':
                raise RuntimeError('Intentional module-target exception')
            response = Response('No debugger trigger supplied\n', mimetype='text/plain')
        else:
            response = Response('Module target\n', mimetype='text/plain')
        return response(environ, start_response)


if __name__ == '__main__':
    application = LabApplication()
    enabled = os.environ.get('WERKZEUG_EVALEX', 'true') == 'true'
    debugger = DebuggedApplication(application, evalex=enabled)
    module_name = application.__class__.__module__
    node = uuid.getnode()
    metadata = dict(version=importlib.metadata.version('Werkzeug'), python=list(sys.version_info[:3]),
                    uid=os.geteuid(), gid=os.getegid(), pid=os.getpid(), username=getpass.getuser(),
                    module_name=module_name, app_name=application.__class__.__name__,
                    module_file=sys.modules[module_name].__file__, mac=':'.join('%02x' % ((node >> shift) & 255) for shift in range(40, -1, -8)),
                    machine_id=Path('/etc/machine-id').read_text().strip(),
                    cgroup=Path('/proc/self/cgroup').read_text().splitlines()[0],
                    evalex=enabled, secret=debugger.secret,
                    pin=getattr(debugger, 'pin', None), cookie_name=getattr(debugger, 'pin_cookie_name', None))
    Path('/run/werkzeug-native.json').write_text(json.dumps(metadata, indent=2) + '\n')
    run_simple('0.0.0.0', 8080, debugger, use_reloader=False, threaded=True)
