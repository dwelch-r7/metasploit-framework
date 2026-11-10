# ActiveMQ FileServer and integrated checkpoint, November 10

This retained checkpoint precedes the
[150-module NiFi scanner checkpoint](VERIFICATION-20261110-nifi.md).

Current input hashes, exact passing counts and owned teardown establish
**148 runtime modules, 76 families and 1,040 functional cases**. This adds
`exploit/multi/http/apache_activemq_upload_jsp` to the retained
[147-module checkpoint](VERIFICATION-20261110-database-capture.md). It is a
selection of qualifying retained runs, not repository-wide completion. WordPress
and the separate Ansible deployer remain in the [deferred index](DEFERRED.md).

The [FileServer guide](activemq_fileserver/README.md) records the genuine
ActiveMQ 5.11.1, removed-FileServer 5.14.0 and unrelated Apache HTTP targets,
verified archive provenance, pins, native controls and limits.

```sh
bundle exec ruby tools/dev/run_module_target_tests.rb activemq_fileserver
```

## Results and attribution

| Invocation | Cases | Failures | RSpec seconds | Meaning |
| --- | ---: | ---: | ---: | --- |
| `20261110T035151-beca56` | 9 | 6 | 223.870815 | Mixed environment and trigger failures. |
| `20261110T041734-26d32e` | 9 | 8 | 335.826658 | Environment corrected; cache/residue cascades remain. |
| `20261110T050952-628f28` | 9 | 1 | 215.861350 | URI/loader fixes isolate cleanup-option failure. |
| `20261110T052138-7beef6` | 9 | 0 | 263.104241 | Guard-only repair; exact same acceptance/native/JSP bytes. |

All runs finish naturally and pass teardown. The final run has no pending or
outside-example errors. Twelve real sessions open and all twelve execute owned
proofs. Coverage includes default Java Spawn=2, Linux x86 Meterpreter and command
shells, default API/custom admin paths, random/custom JSP names, accepted user
role, wrong authentication, removed FileServer and unrelated refusals, with
repeats. Both `AutoCleanup=false` runs preserve the JAR/JSP pair; four explicit
operator `rm` receipts then restore original state. This is preservation followed
by operator cleanup, not automatic module cleanup with the option disabled.

Fresh final native gates pass 102 CLI operations and 33 HTTP requests. Vendor
JMS/queue removal, Java, UID/parent identity, ELF32 execution, actual PUT/MOVE,
JSP compilation, source-provided JAR execution, suffix-specific authentication and
removed/unrelated controls establish the setup independently. Anonymous text-file
PUT policy is not generalized to protected JSP uploads.

The initial six failures are not six independent module defects. Native
counterfactuals show that inherited `JAVA_TOOL_OPTIONS` prints to child stderr
after the SDK closes that pipe, causing SIGPIPE. Spawn=1/2 works when only that
variable is removed. The FileServer-only launcher correction preserves broker
CPU/memory flags in `ACTIVEMQ_OPTS`. The earlier two-second deletion hypothesis
is disproven and retained. No SDK, shared payload or timeout change is used.

The corrected original opens three real callbacks but reusing a JAR pathname
exposes stale Java resource-cache data. Actual SDK execution then raises a
missing-resource exception and leaves temporary residue, contaminating later
checks. Native same-path, distinct-path and public loader-close controls bound
this cause using actual captured JAR bytes. A separate original generated-JSP
variant times out with an SDK bind stack; it is retained as such, not rewritten
as an HTTP 500. Four repaired generated-JSP SDK-main A/B/A/B calls return 200.

## Narrow owning changes

Three source commits remain separate from the lab addition:

- Join custom trigger URI components with the existing normalizer; custom admin
  paths previously requested `/admin<name>.jsp` instead of `/admin/<name>.jsp`.
- Close supported URLClassLoaders in `finally`, avoiding stale same-path JAR
  resources. The public Closeable guard preserves older JVM API behavior; only
  the actual Java 8 target is qualified here.
- Test the Boolean result of case-insensitive cleanup-option comparison. The
  previous integer result was truthy for both String values. The clean 9/1 run
  proves an actual successful false-option session still deletes both uploads
  before this guard is changed.

Focused tests reproduce 20/4 to 20/0 against the precise URI/loader revision,
including 13 owning and seven shared formatter examples. This is not represented
as a comparison against the very original source. Lint passes four Ruby files;
module/doc tidy passes and human Scenarios remain byte-identical. The final
62-key map changes only the guard and focused evidence after the 9/1 runtime;
acceptance, native and generated JSP inputs remain identical.

The parent independently passes all 20 focused examples in 2.444715 seconds,
four-file lint and acceptance-excluded discovery (seven ancillary examples,
zero outside-example errors). This is scoped verification, not a full local suite.

## Evidence and limits

The parent copied and byte-checked all 51 files in the complete final invocation,
preserving original revision, paths, commands and isolated atomic metadata.
All 62 runtime inputs and 64 exported source/documentation files match the
integrated checkout. Exact parent inspection confirms its four final containers
and network absent; there are no volumes. Worker audits verify 32 recorded scoped
IDs absent across eight empty project inventories. The first diagnostic network
ID was not retrospectively recovered; its actual teardown receipt remains.
Earlier dirty SDK-directory names are retained, but their original contents were
not captured. These limits do not disappear from the lineage.

The unchanged export is
`/Users/dwelch/.codex/reports/activemq-fileserver-20261110-4bc44d786ae`.
The parent re-read all 788 entries in `SHA256SUMS`; its SHA-256 is
`27b0dfb21d9a8d32f3f3fa9e022d95ad6adad83f90511fecccb9daf343167243`.
It retains every generation, native diagnostics/counterfactuals, frozen inputs,
actual uploads, sessions, focused comparisons and cleanup. Reader, OpenWire and
Jolokia historical seals remain unchanged; raw evidence stays outside Git.

Parent units/lint/discovery, import/export/current-source/resource receipts,
selected checkpoint, inventory and exact-head CI evidence are sealed at
`/Users/dwelch/.codex/reports/module-target-parent-validation-20261110-578608a173a`.
All 14 checksum entries were re-read. `SHA256SUMS.json` SHA-256 is
`5aca3c58d9aed9d719ae5fc0b1f91b366463d151303172401f0566a9278e6786`.

The previous published revision `179d550d1198ddcf04d301b87b0d2a1380117411`
passes all 14 jobs in its [fork Verify workflow](https://github.com/dwelch-r7/metasploit-framework/actions/runs/42756208981). That result belongs to that
revision, not automatically to this new checkpoint or every acceptance workflow.
No full local RSpec suite was run. Windows/backslash modules, older JVMs, other
architectures/releases, TLS/IPv6, arbitrary contexts and unavailable-API fallback
policies remain unqualified individually. SIP and Gitea are continuing after
retained fixture corrections; NiFi's first attempt stopped before console on
readiness and has no module verdict. Tomcat default Java spawning is being
reassessed separately. The repository-wide goal remains active.
