# November 9 module target verification

This earlier verified checkpoint covered **71 production runtime modules, twenty-five
families and 311 functional cases**. All twenty-four families selected at the
start of the broad shared-validator rerun passed. Subsequent runs strengthen the
modern CouchDB native control and qualify the corrected command-execution profile.
At that checkpoint every selected result had the exact expected count, zero failures/pending/
outside-example errors, matching recorded input hashes and successful owned
cleanup. The [follow-up checkpoint](VERIFICATION-20261109-follow-up.md) supersedes
these totals with 86 modules, 31 families and 416 source-current cases. The
repository-wide campaign remains active.

## MongoDB 2.6 findings and fixes

The original digest-pinned MongoDB 2.6.12 image runs successfully. Its historical
entrypoint lacks initialization hooks, so the lab provisions real users/data
through a temporary localhost daemon, shuts it down, then starts the final open
or authenticated server. Native clients independently validate enforcement,
scoped permissions, actual user digests and all 111 application records.

The complete baseline produced **twelve cases, four failures**, stable inputs
and successful cleanup, at
`tmp/module-target-tests/20261108T235926-b79b07/mongodb_legacy/`:

- Both system-hash cases omitted genuine digests stored as
  `credentials['MONGODB-CR']`; the module handled only the older `pwd` form.
- Both application-cursor cases stopped at 101 of 111 records. Native
  `find().toArray()` and server profiling showed query 101 plus getmore 10,
  while the original library sent an unsupported command and received code 59.

Separate worktrees reproduced and fixed each issue. The library fix is integrated
as `7dd036a8bd9`; the hash-format fix as `4ce05740409`. Native raw captures prove
opcode 2005, batches 101 + 10 and final cursor ID zero. Hash extraction preserves
SCRAM precedence and the older top-level `pwd` fallback. Native 2.6 records and
a native modern capture underpin the regression fixtures; older `pwd` compatibility
and precedence variants are explicitly synthetic.

The combined parent run passed **31 modern cases and twelve legacy cases**, zero
failures/pending/outside-example errors, unchanged inputs and successful cleanup:
`tmp/module-target-tests/20261109T000829-b06e69/`. RSpec durations were 88.34 and
14.46 seconds respectively. A stronger rerun checks absence of real native
MONGODB-CR digests on rejected/restricted requests, as well as SCRAM output. All
43 cases passed again at `tmp/module-target-tests/20261109T001720-9f7017/`,
taking 70.19 and 18.92 seconds. The integrated focused library/module run passed
**124 examples**, including existing support examples. Seven changed Ruby files
pass RuboCop; module msftidy passed in the fix worktree.

Evidence/source/build reports are preserved locally in
`tmp/mongodb-hash-evidence/` and `tmp/mongodb-cursor-evidence/`. One diagnostic
iteration whose library changed during setup was correctly rejected and excluded;
its stable-source replacement passed. No full repository RSpec run was used locally.

Native MongoDB 3.0/3.4, old command cursors, sharding, tailable cursors and injected
network failures remain unqualified. Existing partial-result behavior on
continuation failure/cap is preserved. Credential persistence and password
cracking/JtR format compatibility were not established; the pre-2.6 `pwd` path
has no native target qualification. Modern schema enumeration is excluded from
the 2.6 profile rather than marked pending or assumed functional.

## Mongobleed profile

The lab compares MongoDB 4.4.29 with zlib both open and authentication-enabled,
that release with snappy only, fixed 4.4.30 with zlib, and an unrelated real
Apache service. MongoDB's
[advisory](https://jira.mongodb.org/browse/SERVER-115508) supplies the affected/fixed
release and compression mitigation. A separate native client sends the published
[Wiz one-packet probe](https://www.wiz.io/blog/mongobleed-cve-2025-14847-exploited-in-the-wild-mongodb),
records raw/decompressed bytes losslessly and checks native server configuration.
The vulnerable target returns InvalidBSON; fixed/guarded targets close the
connection. Native HTTP verifies the unrelated service before module checks.

All **eight functional cases passed**, zero pending/outside-example errors,
stable inputs and successful teardown, at
`tmp/module-target-tests/20261109T001159-376093/mongobleed/`. RSpec took 68.79
seconds including a cold console. The first complete run also passed; the
qualified rerun follows a lint-only removal of redundant sorting.

An expanded **eleven-case profile passed** at
`tmp/module-target-tests/20261109T001720-9f7017/mongobleed/` (37.31 seconds,
reusing the invocation's source metadata). A fresh rerun after tightening the
authenticated health check passed all eleven cases in 110.96 seconds at
`tmp/module-target-tests/20261109T002107-79a795/mongobleed/`, with stable inputs,
zero pending/outside-example errors and successful cleanup. The health check
waits for the final authenticated configuration rather than the image's temporary
unauthenticated provisioning daemon.

Checks distinguish vulnerable, fixed, mitigated and unrelated services. Bounded
quick scans test both connection modes twice, with two passes per scan and
offsets 20-512. Actual nonempty binary loot must equal the concatenated decoded
JSON fragments, each recorded length and the total byte count. Normal fixed/
guarded safeguards must produce no loot. Target version queries still succeed
after each scan; these targets have no automatic restart policy. A fresh native
client must receive code 13 when listing databases without authentication on
the authenticated target. Both scan modes still retrieve actual leak loot twice
on that target without providing credentials, qualifying the pre-authentication
path independently of the open target.

Other affected release branches, larger scans, forced exploitation and arbitrary
secret-string recovery remain unqualified.
Memory contents are nondeterministic; the tests require real disclosure and
structural integrity rather than a particular secret. The native proof/script,
images, limits and reproducible commands are tracked with the lab.

## Rsync profiles

All six cases passed on pinned rsync `3.2.7-0ubuntu0.22.04.7` and
`3.2.7-1+deb12u6` at `tmp/module-target-tests/20261109T002516-643192/rsync/`.
The run took 57.74 seconds including console startup, with unchanged inputs,
zero pending/outside-example errors and successful cleanup. The first complete
run also passed before exact package pins and explicit protocol assertions were
added. Both daemons report 3.2.7; native version output and actual greetings
prove different protocol 31.0/32.0 behavior.

Native CLI transfers retrieve exact proof contents from open, authenticated and
hidden shares and reject the wrong password. Module assertions compare actual
listed names/comments, per-share authentication requirements, optional MOTD/
version output, an empty daemon and an independently verified unrelated HTTP
service. The hidden share is genuinely usable but absent from listing. The
uncommented share tests a missing comment rather than inventing a response.
Module documentation checking added no diagnostics; the new Ruby spec passes
RuboCop. Older bare-number greetings, other versions, SSH transport, host ACLs
and persistent report storage remain unqualified.

## SNMP findings and fixes

Forty native CLI controls establish real Net-SNMP 5.9.1 read-only/read-write
policy, wrong-community denial, actual writes and restoration across UDP/TCP,
v1/v2c. The first full suite produced 22 cases/eight failures at
`tmp/module-target-tests/20261109T001859-a39211/snmp/`: six ordinary leading-dot
OID parser failures and both TCP dual-version login cases. A canonical-OID rerun
produced 22 cases/one intermittent TCP dual-version failure at
`tmp/module-target-tests/20261109T002202-34ea87/snmp/`; other main functions passed.

Separate worktrees reproduced both issues. Native numeric OID output itself uses
the leading dot; its module-local normalization is integrated as `23f367268b2`.
The focused eight-case suite passed after reproducing six native failures;
fifteen unit/support examples passed. A separate native TCP capture contains two
valid replies in one read; the original strict decoder rejects the concatenated
stream. Stream framing and its focused regressions are integrated separately
from SET normalization; the parent combined result below governs qualification.
Linux post-module target definitions are also under qualification, without a
passing claim yet.

The TCP fix is integrated as `7ad50bc1ec4`. Its final nineteen framing cases
include coalesced/fragmented replies, the exact two-byte header boundary,
long lengths, size/time bounds, reconnect reset and unchanged UDP behavior.
The parent combined unit/module run passed **34 examples**. Seventeen existing
lint offenses remain in untouched scanner/spec sections; no new SNMP offenses
were introduced. The SET module and new functional suite pass explicit RuboCop;
module msftidy retains its historical lint exemption.

The strengthened parent functional run passed **22 cases** in 106.00 seconds
at `tmp/module-target-tests/20261109T003138-f92c0b/snmp/`, stable inputs, zero
pending/outside-example errors and successful cleanup. Both transport/version
modes and access policies are checked. Dual-version scans must yield exactly
two successful results rather than merely one. Four version/OID-form write
combinations each run twice (eight actual module writes), with native readback
and restoration; dotted-OID negatives verify denied/unknown communities.
Native preflight contains forty CLI controls and the parent records 48 native
exec calls overall. Separate before/after evidence is preserved locally in
`tmp/snmp-set-evidence/` and `tmp/snmp-tcp-evidence/`.

SNMPv3, vendor/Windows MIBs, IPv6, arbitrary SET types, TCP SET and credential
persistence remain unqualified. A passing Linux Net-SNMP profile does not prove
specialist device modules work.

## Linux post-module profiles

The final profile passed **eight cases** in 183.28 seconds including cold
console startup at `tmp/module-target-tests/20261109T004012-b53215/linux_post/`.
All tested input hashes remained unchanged, with zero pending/outside-example
errors and successful owned-project cleanup. Eight native Linux x64 payload
launches opened four command-shell and four Meterpreter sessions; eight fresh
target-side files prove actual session command execution before module work.
Sixty-five native exec records preserve independent controls and readback.

Both declared session types cover Docker detection, normal command paths,
specialist/missing directories on successive runs and exact native configuration
bytes in loot. The OS is genuine Ubuntu 22.04.5 on LinuxKit 7.0.14. Its HTTP
server only supplies readiness. Payloads are generated from current Framework
source/dependencies, staged through a read-only artifact mount and started by
native container exec; no network exploit or SSH login is implied. No binary is
committed. Root sessions do not qualify nonroot permissions, other distributions,
non-Docker runtimes, every optional application config or full-host kernel state.

Initial runs exposed harness assumptions rather than module defects: the console
generation command belongs to payload context; command shells identify as Unix;
absent optional files produce expected diagnostics; and a listed session can
precede completed bootstrap. One setup iteration was stopped after confirming
that race and removed its owned containers. Final setup waits for Framework's
completed open event before commands. Expected missing-file diagnostics must
match natively nonexistent paths; arbitrary module errors are still rejected.
The eight-case final run validates those corrections. The new Ruby spec passes
RuboCop and both existing module-doc edits add no checker diagnostics.

## CouchDB findings and fixes

The original digest-pinned CouchDB 3.3.1 baseline produced **eight cases,
three failures**, with stable inputs and successful cleanup at
`tmp/module-target-tests/20261109T004609-6ecd97/couchdb/`. Independent native HTTP
requests verified actual version, administrator/reader identity, permissions,
database names, full documents and attachment bytes. A real Apache 2.4.62 SPA
fallback returns its unchanged HTML with HTTP 200; it does not emulate CouchDB.

Separate worktrees reproduced and fixed three owning module defects:

- Login used administrator-only user listing as its credential test, missing
  valid readers and accepting unrelated HTTP 200 HTML. It now validates the
  exact identity in a real `/_session` response, including normal AuthBrute and
  older HttpUser option paths. Integrated commit: `28b330eccf5`.
- Enumeration computed authentication without sending it on the initial list,
  then constructed document paths beneath `/_all_dbs`. Requests now share the
  configured authentication and application-relative paths, with response shape
  checks. Anonymous version discovery still precedes CREATEUSER. The separate
  real reverse-proxy diagnostic covers a `/couch/` application root. Integrated
  commit: `ea515770754`.
- CREATEUSER passed an unregistered nil TIMEOUT, discarding the acknowledgement
  after creating the account; it also rejected genuine HTTP 201. It now uses
  HttpClient's normal configurable timeout, validates the actual acknowledgement,
  safely encodes individual JSON strings while preserving duplicate role keys,
  and records the created credential as UNTRIED. Integrated commit: `39c8f1c1d42`.
  Two native ordinary/quoted-credential cases each ran twice in its fix worktree.

Original digest-pinned CouchDB 1.6.1 additionally reproduces actual duplicate-role
privilege escalation on the administrator-configured service. Native controls
verify the created account's real administrator identity and remove it. Admin
party alone is not evidence of authorization bypass. Initial nine-case legacy
qualification exposed three failures; after enumeration/login changes, two
remained: CREATEUSER and anonymous enumeration through public validation.

The latter traced to shared option validation assigning unchanged defaults back
into ModuleDataStore, thereby marking generated credentials as explicit operator
choices. The owning fix preserves unchanged value origins while retaining actual
type conversions and explicit choices, including values equal to defaults.
Original source fails two of 31 focused examples; the corrected option/datastore/
host-parsing suite passes **1,169 examples**. Five new cases cover repeated
validation, explicit choices, numeric conversion, global inheritance and converted
global overrides. Integrated commit: `f0207e9abfc`. Existing lint signatures add
none (55 versus 57 baseline). A separate native public-console diagnostic proves
anonymous requests omit Basic authorization and extract exact binary loot.

The first corrected combined parent run passed **eight modern and nine legacy cases** at
`tmp/module-target-tests/20261109T094229-bfa8c1/`, with zero failures, pending or
outside-example errors, stable tested inputs and successful owned cleanup.
Cases include fixed/affected checks, valid/incorrect/admin/reader credentials,
unrelated HTTP, exact text/binary attachment loot and repeated CREATEUSER with
native identity/roles and explicit operator deletion. The module's intentional
account persistence is not automatic cleanup. Shared validator provenance is now
included in every family's input hashes. All twenty-four established families
passed the broad rerun at `tmp/module-target-tests/20261109T094411-765d69/`.
After review, modern CouchDB additionally verifies that both the original
`/_users/_all_docs` path and the corrected `/_session` path receive genuine
unrelated HTTP 200 HTML. That strengthened eight-case rerun passed in 57.64
seconds at `tmp/module-target-tests/20261109T100640-dec844/couchdb/` and is the
current modern profile selected below.

Native CouchDB 2.x, TLS, credential database persistence and arbitrary proxy
configurations remain unqualified. A 2.1.0 tag lookup failed in both official
namespaces, not proof of infeasibility. Command execution is qualified in the separate profile below; successful
enumeration alone does not prove exploitation. Evidence and
focused captures remain locally in `tmp/couchdb-{login,enum,created-user}-evidence/`.
The integrated parent focused run passed **1,235 examples** across the three
CouchDB module specs and four relevant option/datastore/host-parsing specs. A
separate run of all 25 option-type/container spec files passed **433 examples**.
These overlapping runs are reported separately, not added as unique examples.
The lab/spec Ruby files pass lint; module doc links add no checker diagnostics.

## CouchDB command execution findings and verification

The separate lab reuses original CouchDB 1.6.1 open/admin-party and configured
administrator services, plus 3.3.1 for the fixed-version check. Native controls
verify version, policy and independent query-server execution before module
work. A fresh file owned by `couchdb` is mandatory. The harmless touch command
does not speak CouchDB's query protocol, so CouchDB retries it until its database
is removed. A bounded native HTTP timeout is recorded; timeout/status alone never
proves execution. The normal HttpClientTimeout test option also bounds the
exploit's asynchronous view requests without changing target responses.

The independent native collision probe confirms wrong-password session HTTP 401 before
creation, unauthenticated duplicate-role creation HTTP 201, and session/configuration HTTP 401
afterward. Acknowledgement does not prove usable administrative access. A separate
new username obtains a real administrator session; valid configured administrator
credentials also still work. The corrected one-case baseline permits the real
shadow-account side effect but fails the original module's false bypass success
and stager generation, with stable inputs and owned cleanup.

The owning fix is integrated as `a2427f6a463`. It requires the exact effective
session identity and administrator role before staging. NoAccess explains the
unusable account and possible administrator cleanup. Creation409 still permits
valid existing-administrator execution without calling it a newly completed
bypass. Only actually verified credentials are passed to the existing reporting
API with session proof. Same-spec original source fails **21 of 33 examples**;
final source passes all 33. The parent independently reran those 33 successfully.

The final parent run passed **nine cases** in **253.19 seconds** at
`tmp/module-target-tests/20261109T102445-f4f58e/couchdb_exec/`, with zero failures,
pending or outside-example errors, matching current recorded inputs and owned
cleanup. Ten deliveries each execute a fresh command file owned by `couchdb`.
Cases cover x86/x64 shells, x64 Meterpreter, open/admin-configured services,
default bypass, known administrator and a preexisting-user HTTP 409 path, each repeated
twice. The collision case verifies401 before/after and early refusal. There are
75 native exec records and 18 actual opened sessions; query-process retries can
open additional sessions, so session counts alone are not execution proof.

Native readback distinguishes real cleanup from a race with curl's executable
deletion. An exact-path deletion warning is accepted only when that exact file
is already absent; the writable directory must be empty. Accounts, one database
and two query-server keys can remain after successful exploitation. The test
restores that API state explicitly before repeating; this is operator restoration,
not automatic module cleanup. A rejected collision can leave its shadow account.
The failure warns about it and native operator deletion restores the fixture.

Initial probe/assertion failures were investigated against native behavior rather
than assigned to the module. Extending an intentionally non-protocol command's
HTTP deadline does not make its view finish. Ruby JSON keeps the last duplicate
roles:[] key, so effective roles must be checked through `/_session`. A configured
administrator can legitimately return two `_admin` entries. Handler-disabled
negative tests require AllowNoCleanup to get past Framework's pre-authentication
guard. The final profile corrects all these assumptions.

The worker's nine-case run also passed, in 239.67 seconds. Its exact tested spec and
label-only style change are retained; the parent run above qualifies the final
variant. Evidence/review: `tmp/couchdb-exec-auth-evidence/REPORT.md`. Production
lint adds no signatures (16 existing); both focused/acceptance specs are clean,
module tidy passes and the existing doc link adds no diagnostics.

CouchDB 2.x, intermediate/fixed release boundaries, wget (absent from the stock
image), TLS, arbitrary credential metacharacters, failed-session file cleanup and
credential database persistence remain unqualified. No opaque binary is committed;
payloads are generated from current Framework sources/dependencies.

## Current profile checkpoint

The broad 24-family runner completed with exit zero. Rows use its
`20261109T094411-765d69` artifacts except modern CouchDB (`20261109T100640-dec844`)
and command execution (`20261109T102445-f4f58e`), the final reruns above. Durations
are RSpec execution including console startup, rather than Compose/image setup.
The scan selecting current source/hash results remains in
`tmp/module-target-checkpoint-summary.json`.

| Family | Cases | Seconds |
|---|---:|---:|
| apache_normalize_path | 16 | 60.13 |
| axis2 | 12 | 246.48 |
| couchdb | 8 | 57.64 |
| couchdb_exec | 9 | 253.19 |
| couchdb_legacy | 9 | 15.11 |
| ftp | 13 | 20.75 |
| http | 14 | 12.10 |
| ldap | 10 | 16.98 |
| linux_post | 8 | 195.96 |
| mariadb | 10 | 16.00 |
| memcached | 4 | 10.68 |
| mongobleed | 11 | 38.97 |
| mongodb | 31 | 30.49 |
| mongodb_legacy | 12 | 16.05 |
| mssql2019 | 15 | 19.23 |
| mssql2022 | 15 | 19.45 |
| mysql8 | 10 | 16.40 |
| postgres | 9 | 19.21 |
| redis | 22 | 114.87 |
| rsync | 6 | 25.68 |
| smb | 20 | 46.57 |
| smtp | 9 | 22.33 |
| snmp | 22 | 59.57 |
| ssh | 2 | 16.83 |
| tomcat | 14 | 118.25 |

The 311 cases exclude older diagnostics and overlapping focused unit examples.
The next authoritative DNS fixture has passed 46 native controls and owned cleanup,
but has no Framework module qualification yet and adds no passing coverage.
The complete inventory and per-profile limits remain in the campaign queue.

## Prior pushed-checkpoint CI

The previous pushed revision `0ca4f68e28f` passed Lint and the command-shell,
SSH, SMB, LDAP, PostgreSQL, MySQL and MSSQL workflows. Its
[Verify run](https://github.com/dwelch-r7/metasploit-framework/actions/runs/42541810787)
failed a certificate test because OpenSSL rejects `ms-ntds-sec-ext` as an object
ID. Its [Meterpreter run](https://github.com/dwelch-r7/metasploit-framework/actions/runs/42541811056)
failed on transport/console timeouts in Mettle tests. These are observed failures
on that earlier revision, not proven baseline causes or evidence that later CI
passes. Raw failed logs remain in `tmp/module-container-{verify,meterpreter}-ci-failed.log`.

The subsequent `4044241d4b8` checkpoint passed Lint, SSH, SMB, MySQL, MSSQL,
LDAP and command-shell workflows when inspected. Its
[Verify run](https://github.com/dwelch-r7/metasploit-framework/actions/runs/42599316216)
again failed only the same certificate OID conversion, this time under Ruby 3.4:
16,295 examples, one failure, 664 pending. This confirms the repeated observed
failure, not its baseline cause. Raw logs are retained in
`tmp/module-container-couchdb-verify-failed.log`. Other/new-head CI status must be
refreshed; these results do not imply an entirely green workflow set.

## Checkpoint review

**Summary:** 71 production runtime modules now have passing profiles across
twenty-five families, totaling 311 functional cases. Remaining candidates and
target requirements stay in the campaign/inventory.

**What looks good:** Real upstream services, independent native controls,
before/after regressions, exact data/loot assertions, short bounded scans,
source/input provenance and owned target cleanup.

**Concerns:** Coverage remains limited to declared lab profiles. Tomcat's released
default Spawn=2 dependency failure remains recorded separately; the experimental
external payload candidate is not integrated. A rejected CouchDB
administrator-name collision can leave a shadow user requiring operator cleanup.
Compatibility limits above remain.

**Suggestions:** Continue other useful service/application families and specific
target/session/authentication variants; retain individual feasibility reasons
and investigate failures before classifying them as module defects. No PR exists.
