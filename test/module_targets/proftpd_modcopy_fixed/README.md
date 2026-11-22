# ProFTPD 1.3.5a authentication control

Shares the [native target and test procedure](../proftpd_modcopy/README.md).
Builds genuine 1.3.5a with `mod_copy` enabled. Native authenticated copying and
PHP execution must work before the original owner's unauthenticated check and
explicit exploitation refusal are assessed. One capped container runs at a time
and is removed after each phase.
