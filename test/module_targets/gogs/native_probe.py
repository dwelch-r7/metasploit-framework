"""Run only after an explicit native/runtime grant and actual owned readiness."""
import hashlib
import json
import traceback
from native_client import NativeGogs


def main():
    native = NativeGogs()
    profile = native.profile['profile']
    try:
        for service in native.services:
            native.identity(service)
        native.elf_control(native.services)
        before_state = None
        if profile != 'gogs_hooks':
            before_state = {service: {'state': native.state(service), 'accounts': native.account_states(service)}
                            for service in native.services}
            before_workspaces = native.frame('find', '/tmp', '-maxdepth', '1', '-name', 'native-gogs-*', '-print')
        if profile == 'gogs_hooks':
            for service in native.services:
                native.hook_control(service, 'lab-admin', True)
                native.hook_control(service, 'lab-user', False)
            native.hook_control('prefix', 'lab-hook', True)
        else:
            for service in native.services:
                native.git_exec_control(service)
                native.rebase_control(service, expected_execution=profile == 'gogs_rebase')
                if profile == 'gogs_rebase':
                    native.rebase_control(service, collaborator=True)
                native.access_controls(service)
            if profile == 'gogs_rebase':
                native.rebase_control('gogs', enabled=False, expected_execution=False, ordinary_base=True)
                native.rebase_control('gogs', enabled=False, expected_execution=False)
        # Actual creation credentials, not modern list digests, prove revocation.
        for service in native.services:
            baseline_credential = native.token(service, 'lab-user')  # Actual native CREATE response, never a list value.
            before = native.list_tokens(service, 'lab-user')
            assert native.request(service, '/api/v1/user', token=baseline_credential)[0] == 200
            code, token = native.request(service, '/api/v1/users/lab-user/tokens', user='lab-user', basic=True,
                                          data={'name': 'native-revocation-control'}, method='POST')
            assert code == 201 and native.request(service, '/api/v1/user', token=token['sha1'])[0] == 200
            listed = next(row for row in native.list_tokens(service, 'lab-user') if row['name'] == token['name'])
            fingerprint = hashlib.sha256(token['sha1'].encode()).hexdigest()
            if listed['api_sha1_kind'] == 'stored-sha256-prefix40':
                assert listed['sha1'] == fingerprint[:40] and listed['sha1'] != token['sha1']
                assert native.request(service, '/api/v1/user', token=listed['sha1'])[0] == 401
            else:
                assert listed['api_sha1_kind'] == 'legacy-raw-token' and listed['sha1'] == token['sha1']
            native.revoke_new_tokens(service, 'lab-user', before)
            assert native.request(service, '/api/v1/user', token=token['sha1'])[0] == 401
            assert native.request(service, '/api/v1/user', token=baseline_credential)[0] == 200
            assert native.list_tokens(service, 'lab-user') == before
            native.records['proofs'].append({'kind': 'native-creation-credential-revocation', 'service': service,
                                              'creation_credential_sha256': fingerprint,
                                              'baseline_credential_sha256': hashlib.sha256(baseline_credential.encode()).hexdigest(),
                                              'list_value_kind': listed['api_sha1_kind'],
                                              'listed_digest_auth_before_deletion': 401 if listed['api_sha1_kind'] == 'stored-sha256-prefix40' else 'Legacy raw value equals creation credential',
                                              'creation_auth': '200 before UI deletion,401 after', 'baseline_auth_after': 200,
                                              'restored': native.token_state_summary(before)})

        if before_state is not None:
            after = {service: {'state': native.state(service), 'accounts': native.account_states(service)}
                     for service in native.services}
            after_workspaces = native.frame('find', '/tmp', '-maxdepth', '1', '-name', 'native-gogs-*', '-print')
            assert after_workspaces == before_workspaces, (before_workspaces, after_workspaces)
            for service in native.services:
                for key in ['repositories', 'tree', 'tokens', 'target_tmp', 'framework_tmp']:
                    assert after[service]['state'][key] == before_state[service]['state'][key], (service, key, before_state[service]['state'][key], after[service]['state'][key])
                assert after[service]['accounts'] == before_state[service]['accounts'], (service, before_state[service]['accounts'], after[service]['accounts'])
            native.records['restoration'] = {'before': before_state, 'after': after,
                                             'workspace_before': before_workspaces, 'workspace_after': after_workspaces,
                                             'exact_keys': ['repositories', 'tree', 'tokens', 'target_tmp', 'framework_tmp', 'accounts'],
                                             'app_tmp_and_processes': 'Raw before/after only; provider cache residue is retained'}
            native.records['baseline'] = {service: after[service]['state'] for service in native.services}
        else:
            native.records['baseline'] = {service: native.state(service) for service in native.services}
        native.save('native-gogs-probe.json')
        print(json.dumps(native.records, indent=2))
    except BaseException as error:
        native.records['failure'] = {'class': type(error).__name__, 'message': str(error), 'traceback': traceback.format_exc()}
        raise
    finally:
        native.save('native-gogs-probe-partial.json')


if __name__ == '__main__':
    main()
