import hashlib
import importlib.metadata
import importlib.util
import json
import os
import pathlib
import sys

out = {'uid': os.getuid(), 'gid': os.getgid(), 'python': sys.version.split()[0], 'versions': {}, 'sources': {}, 'texts': {}}
for name in ['langflow', 'langflow-base', 'lfx', 'mcp']:
    try:
        out['versions'][name] = importlib.metadata.version(name)
    except importlib.metadata.PackageNotFoundError:
        out['versions'][name] = None
for package in ['langflow', 'lfx']:
    spec = importlib.util.find_spec(package)
    if spec is None:
        continue
    root = pathlib.Path(next(iter(spec.submodule_search_locations)))
    relatives = ['api/v1/validate.py', 'api/v1/login.py', 'api/utils.py', 'utils/validate.py', 'custom/validate.py', 'services/auth/utils.py',
                 'services/settings/auth.py', 'services/settings/base.py', 'services/settings/constants.py',
                 'main.py', '__main__.py', 'api/v1/endpoints.py', 'api/v1/components.py', 'custom/eval.py', 'custom/utils.py', 'custom/custom_component/component.py', 'custom/custom_component/custom_component.py', 'custom/custom_component.py', 'template/frontend_node/base.py']
    for relative in relatives:
        path = root/relative
        if path.is_file():
            name = package + '/' + relative
            out['sources'][name] = hashlib.sha256(path.read_bytes()).hexdigest()
            out['texts'][name] = path.read_text()
print(json.dumps(out))
