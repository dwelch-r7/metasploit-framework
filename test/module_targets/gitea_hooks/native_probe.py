"""Fresh native hooks/policy controls on genuine Gitea before Framework runs."""
import json
import time
from pathlib import Path
import sys
sys.dont_write_bytecode = True
sys.path.insert(0, 'test/module_targets/gitea')
from native_client import NativeGitea
from native_ui import NativeUI

native = NativeGitea()
started = time.monotonic()
try:
    for service in ['legacy', 'vulnerable', 'fixed', 'locked', 'prefix']:
        native.identity(service)
        native.hook(service, native.admin, service != 'locked', 'admin')
    native.hook('vulnerable', native.user, False, 'ordinary-denied')
    native.grant('vulnerable', True)
    try:
        native.hook('vulnerable', native.user, True, 'explicit-grant')
    finally:
        native.grant('vulnerable', False)
    native.hook('vulnerable', native.user, False, 'grant-revoked')
    # A global hook prohibition still applies after a specific role grant.
    native.grant('locked', True)
    try:
        native.hook('locked', native.user, False, 'locked-grant')
    finally:
        native.grant('locked', False)
    for service in ['legacy', 'vulnerable', 'fixed', 'prefix', 'locked']:
        NativeUI(native, service).hook(native.admin, service != 'locked')
    native.grant('vulnerable', True)
    try:
        NativeUI(native, 'vulnerable').hook(native.user, True)
    finally:
        native.grant('vulnerable', False)
    for service in native.records['profiles']:
        native.records['profiles'][service]['repository_tree'] = native.tree(service)
    assert len(native.records['proofs']) == 5
finally:
    native.records['seconds'] = time.monotonic() - started
    native.save('native-gitea-hooks.json')
print(json.dumps(native.records))
