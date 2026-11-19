# Apache OFBiz native acceptance targets

These serial profiles exercise the XML-RPC, SOAP and ProgramExport owners against
real OFBiz applications and embedded Derby databases. Registration is not a
passing result: the tests keep failing execution and detection cases visible.

| Profile | Image release | XML-RPC endpoint | SOAP endpoint | Unauthenticated ProgramExport |
| --- | --- | --- | --- | --- |
| `ofbiz_17` | 17.12.01 | Enabled without login | Enabled, with an object filter | Available |
| `ofbiz_18` | 18.12.09 | Enabled, requires an authentication bypass | Removed | Available |
| `ofbiz_18_10` | 18.12.10 | Removed | Removed | Available |
| `ofbiz_18_14` | 18.12.14 | Removed | Removed | Available |
| `ofbiz_fixed` | 18.12.15 | Removed | Removed | Permission checked |

Use the repository's existing Ruby bundle, Docker Compose and NASM:

```sh
MODULE_TARGET_NAMESPACE=ofbiz-dev \
  bundle exec ruby tools/dev/run_guarded_module_target_tests.rb \
  ofbiz_17 ofbiz_18 ofbiz_18_10 ofbiz_18_14 ofbiz_fixed
```

Choose one profile for a shorter replay. The guarded runner holds the shared
worktree lock, assigns namespace labels, records source digests and runs each
stack separately. Each stack has only the app and a Framework reporting database.
The app is capped at 1.5 CPUs, 1536 MiB and 256 PIDs; the database retains its
shared smaller limits. Health startup is bounded at 420 seconds and each test
run at 1200 seconds. Finished stacks and their volumes are removed immediately,
including on test failures. Do not add an outer lock around the guarded runner.

Only the TLS app port and reporting database port are published, on random
loopback ports. No debugger port is published or started. The files mounted from
this repository are read-only inspection tools, not replacement app endpoints.

## Provenance and independent controls

[releases.json](releases.json) pins Linux AMD64 image manifests, official archive
SHA-512 checksums and the relevant source-file hashes. Each native gate compares
the container's actual source files with those references before interpreting
module results. The images contain preloaded Derby demo data from `loadAll`;
they do not need a separate target database or an `INIT_DB` initialization step.

The [upstream image recipes](https://github.com/vulhub/vulhub/tree/9b90d4276f84feed6333286afeb7e1250379a1da/base/ofbiz)
build the official source archives. The 18.12 images comment out a host-header
rejection in `RequestHandler.java`. The reference hashes include precisely that
documented change. The 17.12.01 recipe changes Gradle bootstrap/plugin resolution.
These are lab image differences; the profiles do not claim an unmodified
production deployment. The image build's exact historical Git revision is not
available from its metadata.

Before and after module execution, independent Python standard-library requests
verify ordinary login, rejected guest/absent-account access, native entity
listing and real XML-RPC/SOAP ping services or their removal. A valid serialized
Java String checks the XML-RPC extension separately from exploit gadgets.
ProgramExport controls compare a protected direct URL with the unauthenticated
route, exact file bytes, ownership and cleanup. Source hashes and the original
Java PID/start time must remain stable.

The suite then calls the actual owners through msfconsole, including their
`check` and automatic/disabled-check paths. Command proofs cover repeated use,
quotes, backslashes and literal newlines. XML-RPC/SOAP cover an absent base path;
ProgramExport registers no `TARGETURI` option and is limited to its root path.
All three owners cover a closed local port. Bash,
HTTP fetch and x86/x64 Linux dropper tests require used, persisted and closed
sessions. ELF bytes must match the real callback executable. Native callback,
HTTP delivery and executable controls run first. Passive TracePoint evidence
records real owner calls and responses; it does not replace their methods.

## Known investigations and limits

The 17.12.01 native probe confirms that XML-RPC commands work with
AutoCheck disabled, while the existing check cannot find a version on its
XML-RPC response. SOAP's empty-input check reports Vulnerable, but the real
object filter rejects the ROME ObjectBean before executing the command. Those
strict cases remain failures until an applicable repair or supported lab is
verified. A functioning SOAP ping alone does not prove gadget compatibility.

ProgramExport's original implementation also failed commands containing quotes
and printed a failure warning for successfully executed simple commands. The
[verification record](../VERIFICATION-20261119-ofbiz.md) distinguishes the native
counterexamples, focused repairs, failed setup attempts and exact passing replays.
Fresh instances with AutoCheck disabled are exercised independently so a failed
automatic check does not prevent testing manual execution.

Windows targets, default Python-SSL payloads, staged Meterpreter payloads,
unlisted releases and deployment layouts are not qualified here. Existing
human-written module Scenarios are preserved. See the campaign verification
record for actual results; do not infer success from this table or manifest.

Apache documents [security boundaries](https://ofbiz.apache.org/security.html),
including [XML-RPC removal](https://github.com/apache/ofbiz-framework/commit/c59336f604)
and the [ProgramExport permission repair](https://github.com/apache/ofbiz-framework/commit/31d8d7eea12df3fd05f33ffa292f7a50a7cbd3ba).
