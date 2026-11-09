# WordPress Multicall qualification

The selected checkpoint covers **99 production runtime modules, 39 families
and 572 functional cases**. Every selected result has its exact expected count,
zero failures/pending/outside-example errors, matching current recorded input
hashes and successful owned teardown. The preceding
[98-module checkpoint](VERIFICATION-20261109-wordpress-ajp.md) remains current;
Multicall adds one module and 22 cases. The repository-wide campaign remains
active. No pull request was created or full local repository RSpec suite run.

## Target and independent controls

The [reusable lab](wordpress_multicall/README.md) runs genuine WordPress 4.3.1,
4.4 and 6.8.3. Legacy releases use checksum-pinned wordpress.org archives on
official digest-pinned PHP 5.6.40 Apache; the modern subdirectory installation
uses PHP 8.3.28. MariaDB 11.2.2 and unrelated Apache reuse established fixtures.
Legacy image tags have obsolete manifests, so the source download stage uses
current TLS support while preserving the actual legacy application/runtime.

Native PHP checks installed releases, users, roles, inactive plugins and XML-RPC
source hashes. Archive source was compared byte-for-byte against reviewed
official WordPress tags. An independent REXML/Net::HTTP client makes 34 actual
requests before module assertions. It establishes that wrong-then-correct
credentials in one batch yield failure/success on 4.3.1 and failure/failure on
4.4 and 6.8.3. A fresh correct request succeeds afterward, distinguishing the
request-scoped failed-authentication latch from account lockout. Correct
individual credentials and all-correct batches work on all three releases.

The 22 cases cover repeated credential discovery, correct passwords in both
list positions, actual request batch sizes, administrator/subscriber/editor
roles, XML and Unicode passwords, rejected/missing accounts, subdirectory
paths, unrelated HTTP and invalid chunk sizes. Password lists contain at most
two entries; `BLOCKEDWAIT=0` avoids a six-minute cooldown during diagnosis.
Only random loopback ports are published. No host listener or Docker socket
is exposed, and source/configuration remain in the repository.

## Verified failures and repair

After native preflight passed, unchanged production source failed **three of
22 cases**. The old 4.4.1 gate batched passwords on WordPress 4.4, missing a
valid second password. Zero and negative chunk sizes reached `each_slice`
and produced scanner warnings/backtraces. The other 19 cases already passed;
the initially suspected XML builder defect was not reproduced.

The owning module now selects single-password requests starting at 4.4,
rejects chunk sizes outside 1..1700 before network activity, and preserves
the operator's configured value while resetting effective batching per host.
No shared library changes are needed. Configuration preservation and reuse
from a protected host to a legacy host have explicit derived unit regressions,
separate from the three observed functional failures.

- Matched functional comparison: **22/3 -> 22/0** failures. Native preflight
  and teardown pass on both sides; only the owning module differs among the
  recorded input bytes.
- Focused regressions: **30/6 -> 30/0**, comprising 23 owning examples and
  seven shared support cases. Native capture provenance is retained alongside
  the focused spec.
- New specs/probes have no lint offenses. The owning module retains the same
  18 inherited diagnostics; syntax, msftidy comparison and diff checks pass.
- Independent resource inspection found no containers, networks or project
  volumes in either matched project; all four recorded anonymous volumes
  were absent. Unrelated Docker resources were untouched.

## Evidence and limits

Baseline: `tmp/module-target-tests/20261109T171458-b13a24/wordpress_multicall`
(22 cases, three failures, 74.007666 seconds). Final imported worker result:
`tmp/module-target-tests/20261109T172644-fa4d3a/wordpress_multicall`
(22 cases, zero failures, 72.641728 seconds). Durations include cold console
bootstrap and native controls. All 60 imported regular files were verified
byte-for-byte; revision, commands, paths and project identity retain original
worker provenance. Final selected input hashes match the integrated source.
Import receipt: `tmp/wordpress-multicall-import-provenance.txt`.
Aggregate selection: `tmp/module-target-checkpoint-multicall.json`.
Its sole warning names the separate, unqualified WordPress admin draft.

Qualification covers the documented versions and paths. Other versions, TLS,
multisite, plugins/WAFs, lockout, rate-limit cooldown and Framework database
credential persistence remain unqualified. Source-reviewed older release tags
are not extra native deployment coverage. No human Scenarios were generated.

The separate WordPress admin upload draft remains excluded from these totals.
Native controls prove upload permission refusals for editor/subscriber accounts
and an administrator with file modifications disabled. An isolated ordered
20-case comparison reproduces five false-positive checks and passes after a
narrow permission check. That does not qualify the full draft: its original
25-case seed 7721 run reproduces a burst of invalid sessions on the second
staged Meterpreter execution. Controlled interruption preserves raw evidence;
example counts are null, not a 25-case result. Successful generic handler and
ordered-case controls have not established the cause. Session shutdown and
cold-start ordering remain under investigation, with no production session
change justified yet.

At published revision `d8d9d622536`, Lint, SMB, PostgreSQL, SSH, MSSQL, LDAP
and MySQL CI passed; Meterpreter and Command Shell remained queued.
[Verify failed](https://github.com/dwelch-r7/metasploit-framework/actions/runs/42656220295)
again in Ruby 3.4 at `cert_request.rb:251`, where OpenSSL rejects the
`ms-ntds-sec-ext` object identifier with `first num too large`. That source and
its owning spec are unchanged from the campaign base. Its cause remains
unclassified; there is no overall green-CI claim. Inspect each newly pushed
revision separately. Earlier evidence remains recorded in the
[prior verification](VERIFICATION-20261109-jenkins-udp.md).
