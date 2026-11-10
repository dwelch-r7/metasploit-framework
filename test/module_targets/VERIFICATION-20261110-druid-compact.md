# Apache Druid validation checkpoint

The integrated checkpoint is **171 runtime modules, 103 families and 1,310
functional cases**, adding two modules and 34 cases to the
[NiFi credential checkpoint](VERIFICATION-20261110-nifi-credentials.md).
The full campaign remains incomplete.

Thirty-four cases pass across the two Druid exploit modules. The nineteen
earlier JNDI/session cases and fifteen new compact JavaScript cases have
separate immutable evidence. Failed exploratory runs are retained and are not
counted as qualification.

| Profile | Cases / failures | RSpec seconds | Invocation |
| --- | --- | --- | --- |
| `druid_jndi` | 14 / 0 | 402.999761 | `20261110T102808-9703b8` |
| `druid_sessions` | 5 / 0 | 275.817415 | `20261110T102808-9703b8` |
| `druid_js_single_affected` | 14 / 0 | 271.653794 | `20261110T123112-15e8d6` |
| `druid_js_single_fixed` | 1 / 0 | 29.185489 | `20261110T123112-15e8d6` |

All four selected families completed naturally with the exact expected counts,
no pending/outside errors, unchanged selected inputs and successful teardown.
The older seven-container `druid_js` profile remains unqualified: its final
attempt timed out at initial console setup before module execution. Its fifteen
labels are preserved in the compact profiles; they are not counted twice.
The first compact fifteen-case attempt also remains unqualified because its
test observer called protected client readers as public methods.

## Compact JavaScript reproduction and resource scope

Read the [single-release guide](druid_js_single/README.md), then run:

```sh
bundle exec ruby tools/dev/run_module_target_tests.rb druid_js_single_affected druid_js_single_fixed
```

This invocation runs one project at a time. Each has PostgreSQL, ZooKeeper, one
official digest-pinned Druid release, Apache and the canonical Framework service:
five containers, with actual memory limits totaling 2208 MiB and CPU quotas
totaling 2.35 CPUs. Both final inspections found all five services healthy and
no OOM kills. The existing 120-second readiness/console bounds and 600-second
RSpec bound were retained. Container limits exclude Docker VM and host RSpec
overhead; a snapshot is not a peak-memory claim.

The affected 0.20.0 and fixed 0.20.1 native gates passed 32/26 CLI and 17/17 HTTP
controls. They proved authentic JVM/JAR/configuration and application versions,
leadership/metadata, three actual sampled rows, real frontend authentication
and denial, and repeated execution/refusal with independent exact marker bytes,
UID/GID and removal/absence. Genuine Rex sampling then returned the same three
native rows before any module case. Framework obtained a real initial prompt,
returned its isolated BOOT configuration, and published two valid atomic
metadata snapshots; only ordinary within-invocation metadata reuse was used.

The fourteen affected cases retain three positive checks, five meaningful
auth/path/unrelated negatives, five command forms and a quiet command. Every
case repeats twice. Twelve Framework command invocations require independent
same-command native proof before delivery, exact executing CMD/method arguments,
fresh target bytes and state/listener restoration. The fixed check also repeats
twice. A successful response or module exit alone cannot satisfy these gates.

The observer records actual socket-write arguments and full returned byte
counts, genuine peer addresses and responses. It does not generate another
payload or serialize another request. There were 51/3 complete writes and
matching genuine responses in the affected/fixed profiles, including one native
calibration request each; 50/2 were selected-module requests. All actual bytes,
counts and peers matched, with no observer errors. This is **SOCKET-WRITE**
evidence, not PCAP or a receiver-side packet capture. PRE-SEND events are labelled
separately. Strict actual writer JSON, executing input and independent target
proof assertions remain in place.

The native-only feasibility runs, read-only numeric-string Compose parsing
failure, failed compact fifteen-case run and observer correction are preserved
separately. An identical 26-example observer corpus reproduces two failures
before the visibility correction and none afterward. It covers selected-owner
hook delegation, protected visibility, original return/error behavior, exact
bytes and subscriber/write counts. The correction changes only test metadata
observation; no SDK, runner, timeout, dependency or production visibility changed.

## Earlier source repairs and session scope

The [historical shared guide](druid/README.md) and
[session guide](druid_sessions/README.md) describe the original topology and
native prerequisites. Those larger JNDI/session topologies are not eligible for
the current five-container budget without redesign. Their preserved passes
remain separate from the new compact resource result.

Two owning repairs were independently reproduced: JavaScript shell arguments
needed JSON-safe encoding, and JNDI reported failure after genuine payload
execution returned HTTP 500. The JNDI check reason now describes the observed
LDAP injection rather than claiming code execution. Its HTTP 500 acceptance
requires current exploit-phase LDAP search and generated payload attributes;
AutoCheck's earlier lookup cannot satisfy it. Original source-only regressions
were 22/9 before and 22/0 after; independent parent checks also passed 22/0.

The five session cases cover JS Unix netcat, authenticated prefixed wget x64
Meterpreter, wget x86 shell, JNDI Bash, and prefixed JNDI netcat. All ten sessions
opened, were actually used for exact remote proof, and had their target PIDs
disappear before kill fallback. No forced survivor cleanup was needed. Captures
had zero kernel drops and contained four actual ELF HTTP responses. They are
labelled actual wire bytes rather than recovered target files.

Human-written module Scenarios, the historical guides and all their selected
inputs remain unchanged. Pending-status wording in those frozen guides records
their earlier checkpoints; the table above records the completed qualification.
Source lint retains its four inherited warnings and
the JavaScript module document retains five inherited CRLF-related warnings
and one INFO. Actual msftidy returns2 on both sources because of those unchanged
RuboCop findings; JavaScript docs return1 and JNDI docs return0. All ten new Ruby
files lint cleanly. No full RSpec suite or project dependency
installation was performed.

## Inputs, cleanup and limits

Earlier input counts remain 57/57/82, including the unqualified historical JS
profile. The compact profiles each retain 69 current inputs, union 72. Only the
observer differs between the failed compact run and passing replay; case
assertions, module sources, SDK, fixture configuration and guides are identical.
The compact input-map file SHA256 is
`5320c09d0498624c6f56cddcf916c644284d6c8d9ffe3ba775fcc67271f2ea85`.

Both compact projects removed their exact ten containers, ten volumes and four
networks. Independent inspections of every recorded ID/name confirmed absence;
`docker ps -a` was empty at the 12:39:26 UTC terminal audit. Earlier native-only
and failed-runtime projects have their own exact absence receipts. Subsequent
campaign projects are outside this audit. No unrelated object was changed by
the Druid cleanup.

Sampling remains at least once; no exactly-once execution/session promise is
made. Only the documented public CMD ingress, plain IPv4, tested frontend Basic
policies, actual JVM/JAR combinations and listed delivery families are covered.
Windows, built-in Druid roles, a complete analytics cluster, HTTPS, external
brokers, arbitrary console quoting, NTLM/Kerberos/proxy/evasion and unsupported
default Python/curl payloads are not qualified. JNDI's Linux-labelled target
declares Unix; its public compatibility rejection of Linux fetch payloads was
retained.

Raw inputs, actual native/console/socket/packet evidence, original failures,
before/after source maps and exact teardown records are retained in the named
invocations and additive checksum exports. This note records the passing
selection without rewriting any earlier failed result.

## Independent integration checks

Parent imports and byte-checks all 367 files in the two original passing
invocations. All four results and 103 qualified union inputs match the current
checkout. The 105-input all-profile union additionally retains two files from
the unqualified historical JS wrapper. Original 5,684/2,645 documentation bytes
remain in order, with only three-line insertions; both human Scenarios remain
byte-identical. Parent source/observer checks pass22/26, selected dry counts are
14/5/14/1, and six Python syntax checks pass. Initial parent bootstrap/autoload
and append-only documentation assumptions are recorded as observer diagnostics.

Parent independently checks all 299 recorded objects absent:134 containers,
127 volumes and38 networks, plus two temporary native image aliases. Tiny
auto-removed probes retain their explicit ID-preservation limits. These checks
leave the later OpenTSDB lab untouched.

The three independently verified worker manifests retain1,959/829/746 entries:

- `/Users/dwelch/.codex/reports/druid-validation-20261110-72b46e93d6ad`, SHA-256
  `6e2ce7fcedc42372a5ac7d3cd5e606fbc67867b6b30c50f172c959ba1ec781c5`.
- `/Users/dwelch/.codex/reports/druid-low-resource-native-20261110-38cac303e751`, SHA-256
  `03ffb7443ed68bb371f457b55992c2a538a4369ea7ee41c6fe7977ec1713711c`.
- `/Users/dwelch/.codex/reports/druid-qualified-20261110-41b1daf63a7a`, SHA-256
  `a2d7029d762216cf5356bbfdd54188248b4a4b02b6e5f1f38dccc91f29807e6b`.

The39-entry parent receipt seal is
`/Users/dwelch/.codex/reports/module-target-parent-validation-20261110-70202380a0f`,
manifest SHA-256
`4e943678fe1a2f552e042a92ba471a55debf3328f486988f7d228643ac19d157`.
