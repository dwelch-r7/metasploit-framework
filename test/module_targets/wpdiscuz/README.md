# wpDiscuz upload target

These profiles install official checksum-pinned wpDiscuz 7.0.0, 7.0.4 and 7.0.5
on WordPress 5.2.4/PHP 7.3.11 with MariaDB 11.2.2. Vendor code is unchanged.
The minimum release requires the full GIF89a signature; 7.0.4 also accepts the
short GIF8 marker. Both native boundaries are asserted from genuine captures.
Native probes verify ordinary image upload, nonce/post checks, actual PHP marker
execution or refusal, and WordPress attachment cleanup before owner calls.

Prepare with `DOCKER_CONTEXT=default BUILDX_BUILDER=default bundle exec ruby test/module_targets/wpdiscuz/prepare.rb`.
Run one or more named profiles through `tools/dev/run_guarded_module_target_tests.rb`.
For example, use `DOCKER_CONTEXT=default BUILDX_BUILDER=default bundle exec ruby tools/dev/run_guarded_module_target_tests.rb wpdiscuz wpdiscuz_minimum wpdiscuz_prefix wpdiscuz_custom wpdiscuz_guest_disabled wpdiscuz_fixed wpdiscuz_absent wpdiscuz_unrelated`.
The guarded launcher runs them serially and removes each stack and its volumes.
Affected session profiles use three capped containers: app, database and a
Framework console on the same private network. Negative WordPress profiles use
two; unrelated HTTP uses one. Published HTTP ports bind only to loopback.
The app is capped at 0.5 CPU/384 MiB, MariaDB at 0.5 CPU/512 MiB, and
Framework at 1 CPU/1024 MiB, with swap equal to memory and PID limits.
Unrelated HTTP uses 0.25 CPU/128 MiB. Every service uses an init process.

The root profile covers command-only PHP, a PHP command shell, single-stage PHP
Meterpreter and the module's unchanged default staged PHP Meterpreter. Default
cases use `unset PAYLOAD` to remove earlier remembered console selections,
assert the owner's default datastore value, and omit a PAYLOAD override from
the run command. Minimum
version, WordPress subdirectory and custom non-dated uploads exercise the
selected payloads in profiles.json. Each selected delivery runs twice. Native
handlers calibrate the same payloads before the owning module; completed session
bootstrap, remote proof, transport closure and physical uploaded-file cleanup
are verified. Apache worker PIDs can persist normally after a PHP request ends.
The PHP shell executes commands in transient child processes; their status is
captured through the real shell before exit. Meterpreter exposes its live PHP
PID. Neither shell command completion nor an idle Apache worker is a session
transport closure assertion.

Command-only payloads have no session for FileDropper; their remaining files and
WordPress attachment records are removed by explicit native operator recovery
after evidence capture. Session-file cleanup is checked before that metadata
recovery. The mail transport is a local sink. No email delivery is tested.
The guest-upload-disabled profile independently authenticates an administrator
for an ordinary GIF upload while both native and owner anonymous PHP uploads
remain refused. Fixed, absent and unrelated profiles make separate guarded and
AutoCheck-disabled attempts. An absent readme produces an Unknown check and
AutoCheck refusal; this is not treated as a Safe version result.
The existing human module guide and Scenarios remain unchanged.

Qualification evidence and limits are recorded separately in dated verification
reports under `test/module_targets/`. Qualification covers only the recorded
inputs and execution paths.
