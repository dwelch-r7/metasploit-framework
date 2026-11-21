# Explicit PHP Meterpreter source comparisons

These opt-in profiles reuse the [ProjectSend session tests](../projectsend_sessions/README.md)
with the supported per-configuration payload data override. They do not qualify
the installed payload bundle. The ordinary `projectsend_sessions` profile uses
the installed gem and remains separate.

```sh
MODULE_TARGET_NAMESPACE=php-source-check bundle exec ruby tools/dev/run_guarded_module_target_tests.rb projectsend_sessions_control projectsend_sessions_candidate
```

The control uses the exact unmodified decrypted PHP source from the installed
gem. The candidate applies the included source-only `stream_framing.patch` with
the standard `patch` tool. It originates from local metasploit-payloads commit
`cbe78f53c78e084e39ec112ce2e3e1440840d21e`; the patch makes it reproducible without
installing or modifying that checkout. Both modes require baseline source SHA256
`e031bea39090ccc1c3086474c971c00368006e9105aa198d783f94225b36740d`.
The patched source must match
`e17550cce49a90f2a0922242b8697095d35d2c689df0ef3916fb4f104c23f7a1`.
Different installed source fails the setup gate before any owning calls.

Setup checks the gem's complete manifest and encrypted/plain source fingerprints,
then writes only the disposable run configuration's
`payloads/meterpreter/meterpreter.php`. The Framework console verifies the selected
path and digest. Passive events record the actual library read and original stage
generator, including debug settings. Cleanup removes only the expected override
and verifies the original installed gem and full manifest again. No handler,
payload generator or module method is replaced; debugging options are unchanged.

The original native CLI and genuine web-upload gates, default target/payload,
AutoCheck on/off runs, exact UID/bytes/process/socket/SQL proof and strict option
preservation all remain enabled. Native failure withholds dependent owner cases.
A failing preservation assertion stays failing even after sessions work. Source
observations can affect timing, so keep source-comparison results separate from
ordinary installed-gem results and from any inference about historical failures.

One serial stack has three capped services totalling **768 MiB / 1.2 CPUs**:
ProjectSend 384 MiB/0.7 CPU, MariaDB 256 MiB/0.3 CPU and session PostgreSQL
128 MiB/0.2 CPU. Use the guarded namespace/lock and remove the whole stack after
each run. No other containers are needed. Registration is not proof of pass;
consult the dated verification report for actual results and remaining scope.
