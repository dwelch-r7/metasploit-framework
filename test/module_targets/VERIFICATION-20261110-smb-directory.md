# SMB directory and integrated checkpoint, November 10

Current input hashes, exact passing counts and owned teardown establish **168
runtime modules, 98 families and 1,265 functional cases**. Three modules add 32
cases to the [NiFi H2 checkpoint](VERIFICATION-20261110-nifi-h2.md). The full
campaign remains incomplete.

```sh
bundle exec ruby tools/dev/run_module_target_tests.rb smb_directory_users smb_directory_pipes smb_directory_gpp
```

Each profile uses four containers: genuine Samba, its native client, disposable
PostgreSQL and Framework. Ubuntu 22.04 is digest pinned; native controls record
Samba 4.15.13/package 2:4.15.13+dfsg-0ubuntu1.13 and OpenSSL 3.0.2-0ubuntu1.30.
Package versions are observed provenance, not immutable future apt contents.
Six accounts/passwords are public fixtures. No host socket/share, privileged
container, external target or actual domain credential is used.

| Family | Current invocation | Cases/failures | RSpec seconds including console bootstrap | Inputs |
| --- | --- | ---: | ---: | ---: |
| Workstation users |20261110T102538-34273e|11/0|172.458912|69|
| Pipe interfaces |20261110T104317-800734|9/0|357.728334|78|
| GPP files |20261110T105908-b9dbd2|12/0|177.642806|72|

These are 32 current cases across three complete recorded invocations. Zero
pending/outside errors, native controls and owned cleanup pass. Parent verifies
all 96 union inputs against sealed copies and all 604 imported invocation files.
The runtime production revision is `503fc86c629`; the later lab commit retains the
same selected bytes.

There are 64 public operations, eight genuine SMB fixture sessions and 73 native
command records. Every operation repeats. User enumeration covers real logged-on
users, privileged/denied policies, two/one/empty native states, direct/existing
sessions,445/139 and SMB1/2/default3. NetWkstaUserEnum is not an inventory of all
domain accounts: real NetBIOS139 holders populate it, while direct445 is empty.

The pipe auditor retains its complete 215 UUID/version pairs in exact order.
Current output has 3,440 interface rows and 16 OPEN rows; native Samba independently
binds 645 combinations. BROWSER/missing-pipe negatives remain genuine. SAMR1.0
and management1.0 are actually exposed on samr. GPP covers nine real SYSVOL XML
locations, independent AES/UTF-16 decryption and recovered-account authentication,
STORE true/false, SMB sessions,139, missing/empty/unreadable shares and bad auth.
It produces 180 byte-exact loot files and 24 authenticated 42-byte file proofs,
with stdout/stderr/status retained separately. Reported credentials remain
Untried; independent authentication is distinct from module discovery.

Four separate source commits fix UTF-16LE→UTF-8 password decoding/data-source
names, nullable workstation fields, session credential ports and default pipe
write framing. Native 228-byte NDR reproduces the null-pointer failure. Identical
688-byte BIND data gets an ACK in one write (0.034s), but captured 256/189/243-byte
writes hit the existing 60-second read bound. Two whole-write native audits bind
430 interfaces. The module defaults to 1024-byte minimum/maximum, fitting the
actual default 732-byte maximum BIND. Existing Option.fallbacks preserves explicit
module/global minima and smaller selected maxima. No shared RPC/SMB SDK or timeout
change; explicit fragmentation can still reproduce this Samba limit.

Matched focused evidence is 18/5→18/0 for the generic parser,22/7→22/0 for three
owners, and 13/4→13/0 for explicit-bound compatibility. Counting shared formatting
examples once gives 46/0; parent independently repeats 46/0. Actual writer coverage
preserves the captured732 bytes as512+220 under a selected512-byte maximum.

Original runtime records preserve users 11/9, GPP 12/8 and an unqualified 600-second
pipe deadline. Corrected-original users 11/5 and GPP 12/7 establish the real null,
Unicode and session-port faults before source repairs. The repaired 32-case run initially has
11 failures from test observers: binary-loaded module Strings differ from UTF-8
literals in Marshal tags, and a binary console buffer rejects UTF-8 expectations.
Exact decoded note values, unchanged raw repeated rows and exact password bytes
correct those observers without changing production. Database encoding stripping
is not claimed.

A later GPP 12/6 reaches correct account reads but merges transfer-status stderr
with exact42-byte stdout through the shared capture2e helper. A family-only
capture3 reader, two real positive authentications and wrong-password refusal
establish the correction before final 12/0. An initial outer smoke-message oracle
was also corrected and retained. Strict output/credential/loot/repeat assertions
remain; no shared helper was weakened.

The resource-limit instruction arrives during the pipe replay. Its natural 9/0
is preserved; holding the pending GPP manifest before lookup prevents any next
startup, then the identical file is restored after runner exit. That intentional
setup cancellation has no module verdict. Subsequent smoke and GPP runs are
serial. The [campaign limit](CAMPAIGN.md#local-execution-limit) permits one project
and at most five test containers; larger profiles remain queued for splitting.

Parent verifies all 2,587 entries in
`/Users/dwelch/.codex/reports/smb-directory-module-validation-20261110-830ef713dd86/CHECKSUMS.sha256`,
manifest SHA-256
`b35e8bfb10877b94b79dc12e5b9eaffeb7a6c3b6bfdffcbdf29148e30b4612c8`.
Nine new Ruby files lint cleanly. Four production files retain 97 inherited
cop/message diagnostics with none new; all three modules pass actual msftidy.
Docs retain 11 warnings/one INFO and every original human-written byte. Parent
selected dry 11/9/12 and excluded 7 pass; Python syntax passes. No full local RSpec
suite was run. Initial parent manifest-name, heading and diagnostic-identity
observer mistakes are recorded separately from corrected passing checks.

All 147 parent cleanup checks pass: 55 exact container IDs, 18 network IDs, 14 known
volume IDs and 60 label checks over 20 project names (19 created, one cancelled).
The first schema smoke lacks its former anonymous volume ID; successful down
and label absence are retained without inventing exact-ID proof. Images remain
caches. Parent 55-entry receipt seal:
`/Users/dwelch/.codex/reports/module-target-parent-validation-20261110-2b5b54332dc`,
manifest SHA-256
`171c254651fc1d1512b57060e35e86918fbede71de9b57093611ce54850207d4`.

Windows/AD behavior, Windows GPO application, live session ports other than 445
and pipe 139/automatic fallback remain unqualified. Focused port regressions cover
139. The shared GPP parser also serves the Windows post module and XML importer;
parser contracts are tested, but their complete workflows are not claimed.
