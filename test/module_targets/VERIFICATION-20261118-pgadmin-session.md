# pgAdmin execution and repairs, 2026-11-18

Qualified four profiles for `exploit/multi/http/pgadmin_session_deserialization`,
adding **one owner and 31 cases**: **293 runtime owners in covered paths, 594
qualified profiles and 4,142 historical functional cases**. Final aggregate
`20261118T101114-128a68` passes **31/0**, CLI exit 0, zero pending/outside errors and successful
teardown. Twelve inline Python Meterpreter/command-shell sessions recover their
selected state. Staged Meterpreter recovery remains a separate **unqualified**
9/2 diagnostic. The broader campaign remains active; no PR is created.

## Reproduction and native prerequisites

The [shared target guide](pgadmin_session/README.md), linked from the existing
module documentation, keeps Compose profiles, source/image pins and tests together:

```sh
bundle exec ruby tools/dev/run_guarded_module_target_tests.rb pgadmin_session pgadmin_session_prefix pgadmin_session_storage pgadmin_session_fixed
```

Official pgAdmin 8.3 and 8.4 linux/amd64 manifests and expected image configuration
IDs are pinned in [profiles.json](pgadmin_session/profiles.json), with upstream
commit and exact session/file-manager source hashes. Vendor handlers and the
entrypoint are unchanged. Profiles select the stock root, documented Gunicorn
`SCRIPT_NAME=/pgadmin`, or configured `/var/lib/pgadmin/Spaced café storage`.
No external PostgreSQL service is required for this authenticated storage path.

Each fresh project has one container, one CPU, 512 MiB memory/equal swap, PID128,
init and four Gunicorn threads. Only a random loopback HTTP port is published.
Postfix is disabled. Framework uses the existing host Ruby 3.3.13 bundle on
macOS 26.7.2/x86_64, with Python 3.14.6 standard-library controls. The target uses
Python 3.11.6 on 8.3 and 3.11.8 on 8.4. Docker 29.9.3 / kernel
7.0.14-linuxkit remains on the same engine throughout the compared cohorts.

Independent controls validate installed version/source/UID5050, invalid and valid
passwords, actual storage upload/exact bytes/deletion and accepted uppercase login.
Separate relative/absolute pickle canaries execute on 8.3 and remain absent on
8.4. Nothing is unpickled on the host and HTTP status alone is insufficient.
The first standalone native success precedes loading the owner. Final before/
after groups create twelve exact UID5050 markers and prove four patched absences.

## Qualified functional results

| Profile | Cases | Genuine sessions | RSpec seconds |
| --- | ---: | ---: | ---: |
| `pgadmin_session` | 9/0 | 4 | 117.3 |
| `pgadmin_session_prefix` | 9/0 | 4 | 84.2 |
| `pgadmin_session_storage` | 9/0 | 4 | 86.0 |
| `pgadmin_session_fixed` | 4/0 | 0 | 51.0 |

Every vulnerable profile covers the real check, handler-free command execution,
uppercase credentials, invalid-password refusal, an unrelated base path, inline
Python Meterpreter and Python command-shell sessions, and both family repeats.
First executions use AutoCheck; repeats disable it and reuse the actual console
configuration. The patched profile checks Safe, normal AutoCheck refusal, forced
command nonexecution with genuine upload/deletion, and unrelated-path rejection.

Every session registers through Framework and its ready event, performs a real
file operation, proves exact bytes/UID5050 independently and exposes a real live
target TCP socket. Meterpreter file channels return to their prior set. The shell
payload creates a fresh command shell per request; its reported command PID is
not treated as a persistent session process. Public session termination is followed
by independent absence of established/CLOSE_WAIT sockets for that listener.
Proof/upload files are checked absent and local sessions/jobs finish empty.
No shared application worker is forcibly signalled or required to disappear.

Passive source-scoped traces record 25 checks, 22 authenticated exploit entries,
19 uploads/triggers/deletions and three authentication refusals. All **40 resource-
event captures are zero**. All **twelve individual containers, volumes and networks**
are independently confirmed removed, and both Docker contexts finish empty.
This is selected-state recovery, not whole-filesystem/process-table equivalence.
All **58 final input files** match their captured SHA256 values before sealing.

## Repairs and preserved failures

The original owner guesses storage from the supplied email. Genuine uppercase
credentials are accepted, but pgAdmin stores the file under its canonical lowercase
account. Original 7/1 becomes 7/0 when only the owner changes among 42 frozen inputs.
The repair uses the server's actual absolute upload location, validates metadata,
preserves the upload helper's true return through an optional block and attempts
known-filename deletion on invalid metadata without replacing the primary error.

A configured space/Unicode storage path exposes a second issue. Native WSGI
Request.cookies receives raw UTF-8 as mojibake; octal-escaped UTF-8 is accepted.
A standalone Ruby cookie-parser round trip does not model that request path.
Custom-storage 4/2 becomes 4/0 when only the owner changes among 41 inputs.
The Framework serializer is retained, then non-ASCII bytes are octal-escaped;
existing ASCII and default SMB wire behavior remain unchanged. Windows path cases
are synthetic and do not establish Windows runtime support.

Under the URL prefix, correct and wrong login submissions both redirect to the
application root. The original owner falsely announces successful authentication
before the protected operation denies access. The repair verifies the existing
file-manager transaction before printing success and reuses it for upload, adding
no duplicate request. A 51-input owner-only replay removes that failure: 7/3 becomes
7/2, with only the independently identified inline payload errors remaining.

The threaded Python pickle invokes builtin exec from Thread.run, whose default
globals and locals differ. Inline Meterpreter then raises EXPORTED_SYMBOLS NameError.
The [library contracts](../../spec/lib/msf/util/python_deserialization_spec.rb)
execute real bounded CPython code: **18/8 → 18/0 → 18/0**. A fresh explicit globals
dictionary supplies the same locals and isolates each invocation; the protocol-zero
reference generator changes with it. In-place execution and public return shapes
remain unchanged. Native diagnostic execution subsequently proves staged and inline
Meterpreter file operations twice each, including restored inline execution/recovery.
Other BentoML, Taiga and InvokeAI applications are not qualified by these unit tests.

The first expanded aggregate is 29/9: root 11/4, prefix 7/3, storage 7/2 and fixed
4/0, with all native controls and teardown passing. A helper-only 49-input replay
corrects local session termination order but still finishes 11/4; staged target
sockets now remain CLOSE_WAIT. The separate strict Meterpreter profile finishes
**9/2**, with four actual API/file proofs, both inline recoveries passing and both
staged closure assertions failing. Its twelve resource-event captures are zero,
native controls pass and all three Docker objects are independently removed.

The installed Python Meterpreter 2.0.257 has no explicit normal-shutdown transport
deactivation. That supports investigation, but does not prove remote shutdown
handler execution or the live reference-retention cause. Existing healthchecks
already succeed every three seconds. No extra health/GC workaround or PID signal
is used. The [deferred record](DEFERRED.md) retains the bounded next discriminator.
The diagnostic remains excluded from qualified totals and the four-profile command.

Earlier native setup mistakes (major-only version assertion, then HTTP method
logging) precede owner qualification. Parser calibration and a missing-Location
redirect-helper assumption are preserved separately. Final module/path/auth
contracts pass **62/0**; namespace contracts pass **18/0**, with zero pending,
outside or support examples. Syntax, changed module/helper/spec RuboCop, msftidy
and module-doc checks pass. The shared library retains one identical old
Layout/EmptyLinesAroundMethodBody offense (original line24, current25); no new
RuboCop offense is introduced. The full local RSpec suite is not run.

## Evidence and remaining scope

Immutable raw/input capsules live under `~/.codex/reports/`; each has SHA256SUMS.json.
The final capsule includes the scoped audit, current focused checks and receipts
for original, repair, calibration, diagnostic and source-analysis evidence.

| Cohort | Capsule | Manifest SHA256 |
| --- | --- | --- |
| Independent native controls | `pgadmin-session-native-20261118t083234` | `7545c4e103e9307ea78edbb4419548e4c1c9ccae221da719d163bfa82b87c3db` |
| Original owner | `pgadmin-session-original-20261118T084223-1ba173` | `a5619933b7a16654cbd86adc742392b9f1e27fb0bea97984652e7d252cb07b57` |
| Storage-path repair | `pgadmin-session-replay-20261118T090127-fc51da` | `e386e893db7f97a913f5152623186bb199b01fb04f7e610d3060aca12398c1de` |
| Unicode original | `pgadmin-session-storage-original-20261118T092242-8ef334` | `2802d67980e259e52b6f8e1177dbeb9e6e430380e56fc2d1aa1e013a36aca779` |
| Unicode repair | `pgadmin-session-storage-replay-20261118T092928-f2bb10` | `20af2aea280d897d146915dca2266c52aca3d120efebedb06625d262c96362da` |
| Authentication repair | `pgadmin-session-auth-replay-20261118T095559-7d3060` | `0d1fcc106e1cb3048fa2b29d8f6316f8d0acbcc333911b1df3e618b6af068998` |
| Strict Meterpreter diagnostic | `pgadmin-session-meterpreter-diagnostic-20261118T100318-0de573` | `6d5f2882203670f27323158248f60335dcfa4760e0d4b0d26559b80a509763ec` |
| Final qualification | `pgadmin-session-qualified-20261118T101114-128a68` | `5454138ccd632e80189b6a436b7e75cbbcef60baa1b26e8ff306ecf87f8fedb1` |

The final capsule contains 733 files. Separate repair-contract and exact
installed-payload-source capsules preserve detailed before/after tests and the
shutdown analysis. The diagnostic's later guide wording adds the now-proved inline
qualification; its executed Ruby/Python/Compose/manifest bytes are unchanged.

Windows authenticated/UNC/SMB, other releases/architectures, TLS, real proxies and
transport loss remain unqualified. Existing human Scenarios remain unchanged.
The prior published head dcf17cf944a3 has eight successful workflows and two separate
CI failures: Chocolatey timeout before command-shell checkout/tests, and actual-source-
verified Windows PHP5.3 Meterpreter 82/1 interrupted in post/test/cmd_exec. Causes
and earlier unrelated Mettle results remain separately recorded, with no reruns or
cancellations. New-head CI requires its own observations and checkout evidence.

The static inventory remains 5,179 source files, with
**4,302 pending selectable candidates**, 225
pending documented container hints and zero stale source reviews. Registration
alone is not qualification; the goal remains active.
