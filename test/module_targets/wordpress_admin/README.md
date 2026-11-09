# WordPress administrator plugin upload

**This family remains unqualified.** Native controls pass, and the separate
upload-permission check repair is verified, but a second staged PHP Meterpreter
execution can enter an invalid-session reconnect burst during bootstrap. Keep
this reproducer available for investigation; it is excluded from passing totals.
The failure is not established as an upload-module defect.

From the repository root:

```sh
bundle exec ruby tools/dev/run_module_target_tests.rb wordpress_admin
```

To reproduce the observed cold-state ordering, temporarily add `--seed 7721`
to this worktree's `.rspec-local`, preserving existing contents, and run the
command above. Remove only that temporary option afterward.

That order starts with the repeated root staged-Meterpreter case. Two full-suite
comparisons required controlled interruption before later-case cascades; their
final counts are null. A bounded single-case observer run completed with one
failure and successful teardown. Explicit remote exit and verified prior-handler
shutdown did not resolve it. Saved TLV observations narrow the next investigation
to bootstrap/`core_loadlib` and packet transport; they lack session/socket labels
and do not establish network silence. No production session fix is claimed.

This family exercises `exploit/unix/webapp/wp_admin_shell_upload` using the
[shared digest-pinned WordPress 6.8.3/PHP 8.3 lab](../wordpress/README.md).
Root and `/wordpress/` installations permit administrator uploads. A separate
root installation enables WordPress's genuine `DISALLOW_FILE_MODS` policy through
PHP configuration; it retains working administrator authentication while denying
plugin installation. Non-administrator fixture accounts and genuine unrelated
Apache provide additional negatives. Separate databases and disposable state
remain within the owned project. Only random loopback target ports are published;
reverse listeners stay on the internal Framework container network.

Native PHP runs as `www-data` and inspects actual roles/capabilities, installation
paths, writable directories, filesystem method and available command execution.
Independent HTTP controls establish authenticated profile identity, valid and
invalid credentials, and actual administrator/limited-account upload permissions.
An independent RubyZip/Net::HTTP client installs and executes a harmless proof
plugin twice per normal installation, verifies web-account process execution and
exact target-file proof, then removes it through WordPress's own plugin API.
The real runtime also verifies native PHP callbacks into an internal standard
Ruby TCP listener. No module login, upload, ZIP or payload helper implements these
native controls.

Twenty-five functional cases cover administrator upload checks, valid limited
accounts, wrong/absent users, disabled file modifications, unrelated HTTP,
non-session PHP execution and command-shell, staged Meterpreter and stageless
Meterpreter sessions across both installation paths. Every successful execution
path runs twice. Sessions must create a fresh file as the web account and remove
their uploaded plugin and package archives automatically. The non-session case
explicitly consents to `AllowNoCleanup` and tests operator cleanup separately;
it does not claim session-driven cleanup for a payload without a session.

Failed-case recovery removes only artifacts created after the case's native
snapshot, after assertions have already determined the result. Recovery cannot
turn a failed module-cleanup assertion into a pass. Native commands, response
captures, source hashes, exact counts and owned teardown are retained according
to the [shared guide](../README.md). Registration is not qualification, and no
human module Scenarios are generated. Other WordPress/PHP versions, operating
systems, remote filesystem methods, TLS, plugin activation and Framework database
credential persistence require separate qualification.
