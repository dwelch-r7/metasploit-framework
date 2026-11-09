# November 9 module target verification

The previous checkpoint covers 226 passing cases across seventeen families and
60 production runtime modules. This batch qualifies MongoDB's older protocol
and a separate bounded Mongobleed profile. The repository-wide campaign remains
active; a passing profile does not establish every supported configuration.

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
its stable-source replacement passed. No full repository RSpec run was used.

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

## Checkpoint review

**Summary:** 65 production runtime modules now have passing profiles across
twenty-one families, totaling 277 functional cases. Remaining candidates and
target requirements stay in the campaign/inventory.

**What looks good:** Real upstream services, independent native controls,
before/after regressions, exact data/loot assertions, short bounded scans,
source/input provenance and owned target cleanup.

**Concerns:** Coverage remains limited to declared lab profiles. Tomcat's released
default Spawn=2 dependency failure remains recorded separately; the experimental
external payload candidate is not integrated. Compatibility limits above remain.

**Suggestions:** Continue other useful service/application families and specific
target/session/authentication variants; retain individual feasibility reasons
and investigate failures before classifying them as module defects. No PR exists.
