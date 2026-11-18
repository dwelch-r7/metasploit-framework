"""Deterministic task-owned target environment; no host environment is copied."""
import pwd


def environment_for(user, variant):
    assert user in ['root', 'labuser']
    assert variant in ['standard', 'large']
    account = pwd.getpwnam(user)
    values = {
        'PATH': '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin',
        'HOME': account.pw_dir,
        'USER': user,
        'LOGNAME': user,
        'LC_ALL': 'C.UTF-8',
        'MODULE_TARGET_ENV_SIMPLE': 'module-target-value',
        'MODULE_TARGET_ENV_EMPTY': '',
        'MODULE_TARGET_ENV_SPACE': 'module target value',
        'MODULE_TARGET_ENV_EQUALS': 'left=right==',
        'MODULE_TARGET_ENV_UNICODE': 'café λ',
        'MODULE_TARGET_ENV_MULTILINE': 'line one\nline two',
    }
    if variant == 'large':
        values['MODULE_TARGET_ENV_LONG'] = 'A' * 65536 + 'MODULE-TARGET-END'
    return values
