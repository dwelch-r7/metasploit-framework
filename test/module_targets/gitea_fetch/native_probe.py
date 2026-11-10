"""Prove real migration behavior, branch fix and policy independently of Framework."""
import json
import time
import sys
sys.dont_write_bytecode = True
sys.path.insert(0, 'test/module_targets/gitea')
from native_client import NativeGitea, PROFILES
from native_ui import NativeUI

native = NativeGitea()
started = time.monotonic()
try:
    for service in ['vulnerable', 'fixed', 'prefix', 'blocked']:
        native.identity(service)
    for service in ['vulnerable', 'fixed', 'prefix']:
        actor = PROFILES[service][2];owner = native.user[0]
        seed, migrated = 'module-target-native-seed', 'module-target-native-migrated'
        proof = '/tmp/module-target-native-fetch'
        for malicious in [False, True]:
            before = native.tree(service)
            native.command(actor, 'test', '!', '-e', proof)
            try:
                status, metadata = native.request(service, '/api/v1/user/repos', native.user, {'name': seed, 'auto_init': True, 'private': False})
                assert status == 201 and metadata['default_branch'] == 'master', (status, metadata)
                base = 'http://prefix/gitea/' if service == 'prefix' else 'http://'+service+':3000/'
                metadata['clone_url'] = base+owner+'/'+seed+'.git'
                command = "sh -c 'id > "+proof+"; printf \"SELF=%s PPID=%s\\n\" \"$$\" \"$PPID\" >> "+proof+"; cat /proc/$$/status /proc/$PPID/status >> "+proof+"'"
                settings = {'repository': owner+'/'+migrated, 'metadata': metadata, 'command': command if malicious else None}
                assert native.request('migration', '/configure', data=settings)[0] == 200
                status, document = native.request(service, '/api/v1/repos/migrate', native.user, {'repo_name': migrated, 'repo_owner': owner, 'clone_addr': 'http://migration:8000/'+owner+'/'+migrated, 'service': 'gitea', 'pull_requests': True, 'auth_token': 'public-native-token'})
                observed_status, observed = native.request('migration', '/observations')
                assert observed_status == 200 and observed['requests'], observed
                result = {'service': service, 'malicious': malicious, 'status': status, 'response': document, 'observations': observed}
                if not malicious:
                    assert status == 201, result
                    actual = native.command(actor, 'git', '--git-dir', '/data/git/repositories/'+owner+'/'+migrated+'.git', 'rev-parse', 'master', user='git').strip()
                    expected = native.command(actor, 'git', '--git-dir', '/data/git/repositories/'+owner+'/'+seed+'.git', 'rev-parse', 'master', user='git').strip()
                    assert actual == expected
                    result['master_commit'] = actual
                else:
                    assert status == 500, result
                    actual = native.command(actor, 'sh', '-c', 'if test -f '+proof+'; then cat '+proof+'; else printf ABSENT; fi')
                    if service == 'fixed':
                        assert actual == 'ABSENT', result
                    else:
                        assert 'uid=1000(git)' in actual and 'Name:' in actual, result
                        assert native.command(actor, 'stat', '-c', '%u:%g', proof).strip() == '1000:1000'
                    result['execution_proof'] = actual
                native.records['proofs'].append(result)
            finally:
                for name in [migrated, seed]:native.remove_repo(service, owner, name, native.user)
                native.command(actor, 'rm', '-f', proof)
            assert native.tree(service) == before
    before = native.tree('blocked')
    assert native.request('migration', '/configure', data={'repository': 'blocked/native', 'metadata': {}, 'command': None})[0] == 200
    for iteration in range(2):
        status, document = native.request('blocked', '/api/v1/repos/migrate', native.user, {'repo_name': 'module-target-native-blocked', 'repo_owner': native.user[0], 'clone_addr': 'http://migration:8000/blocked/native', 'service': 'gitea', 'pull_requests': True})
        assert status == 422 and document['message'] == 'You can not import from disallowed hosts.', (status, document)
        assert native.request('blocked', '/api/v1/user/repos', native.user) == (200, [])
        assert native.tree('blocked') == before
    assert native.request('migration', '/observations')[1]['requests'] == []
    for service in ['vulnerable', 'fixed', 'prefix', 'blocked']:
        NativeUI(native, service).migration(service != 'blocked')
    for service in native.records['profiles']:
        native.records['profiles'][service]['repository_tree'] = native.tree(service)
    assert len(native.records['proofs']) == 6
finally:
    native.records['seconds'] = time.monotonic() - started
    native.save('native-gitea-fetch.json')
print(json.dumps(native.records))
