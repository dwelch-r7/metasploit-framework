# Module container validation campaign

## Acceptance

Review the complete source inventory for container feasibility and practical
value. For feasible, valuable modules, retain reproducible target definitions
and quick automated tests in the repository, linked from module documentation.
Exercise main functions with meaningful results and useful variations. Validate
target setup independently before classifying failures. Record genuine module
failures for investigation or fix them in a separate worktree. Exclude targets
only with a specific feasibility reason. Publish cohesive verified commits to
the author's Framework fork without creating a pull request.

## Local execution limit

The current campaign runs one test Compose project at a time, with at most five
running test containers including Framework and helpers. Builds, native smoke
projects and cold console starts share the same serial queue. Confirm the prior
project is down before starting another. Larger profiles must be split into
sequential releases/scenarios or remain queued; the resource limit is not evidence
that their modules are infeasible or broken. Only containers for this campaign
may run on the development host. Remove unrelated containers before starting;
preserve their images and volumes unless separately requested.

Use `tools/dev/run_guarded_module_target_tests.rb` for subsequent local runs.
Its user-scoped advisory lock spans worktrees and teardown, and its merged
Compose preflight refuses more than five containers or any existing container.
Resource refusals carry no module verdict. The original runner and manual/native
launchers remain outside the lock and require the same serial coordination.
The guard counts all resolved services conservatively and does not impose CPU
or memory ceilings; retain those limits in each profile. Historical larger
profiles remain qualified only for their recorded inputs and must be split for
local replay.

The [guard verification](VERIFICATION-20261110-resource-guard.md) records 21
focused passing examples and a real nine-container Compose refusal with no
startup, unchanged empty inventory and released lock. Existing module coverage
remains 173 modules, 107 families and 1,359 functional cases.

## Activity

The first batch establishes the runner, complete static inventory and Redis,
Apache HTTP, Memcached and PostgreSQL labs. The inventory found 5,153 Ruby module
source files on upstream revision `7673832c306`; 392 module documents initially
contained container hints. Neither figure is a count of viable target labs.
No module has been excluded as infeasible yet.

The first stable checkpoint passed all 61 cases across five families and 20
registered modules. See [the verification snapshot](VERIFICATION-20261108.md)
for exact versions, durations, evidence paths and remaining limits. The source
inventory now also includes Python and Go, distinguishing supporting code and
payload components from selectable module candidates.

The subsequent MySQL/MariaDB addition passed 20 more cases with strengthened
hash/account assertions. Verified coverage now totals 25 registered runtime
modules in seven families and 81 cases; the same verification snapshot records
its evidence and limits.

Redis recovery qualification expanded its suite to 22 cases, corrected a native
configuration-query assertion, and reproduced/fixed upload failure cleanup.
The current verified checkpoint is 25 modules, seven families and **85 cases**.
The snapshot records the corrected baseline, final run and transport limitations.

Managed SSH and Samba labs subsequently passed two and 20 cases respectively.
The verified checkpoint is now **33 runtime modules, nine families and 107 cases**.
The new console-container path reuses the canonical Dockerfile with a small
dependency context and read-only current source. It enables normal service ports
and reverse listeners on the isolated target network. Tomcat qualification is separate and does not yet count as a pass.

The SQL Server 2022 addition then passed 15 cases, including exact native hash
comparison and seeded schema/query results. The current verified checkpoint is
**39 runtime modules, ten families and 122 cases**. Tomcat remains under
investigation after seven failures in its first complete 12-case run.

SQL Server 2019 then passed the same 15-case suite on its native authentication
defaults, bringing the verified checkpoint to **39 modules, eleven families and
137 cases**. Within one invocation, source-metadata reuse cuts repeated console
startup while retaining fresh configuration and normal checksum validation.
Ten families passed the eleven-family regression invocation; Redis encountered
a binary-output logging defect in the harness, then passed all 22 cases after
lossless logging was corrected. The invocation itself did not return success.

Tomcat subsequently passed all fourteen session/login/check/native-executable
cases after four separately reproduced corrections. The cumulative verified
checkpoint is **42 modules, twelve families and 151 cases**. Axis2 is being
qualified next; its current presence in the repository is not a passing result.

The managed LDAP suite then passed ten cases using the existing seeded Samba
fixture, covering five more modules through session and direct-host read paths.
The current cumulative checkpoint is **47 modules, thirteen families, 161 cases**.
Its documented SYS_ADMIN requirement was established by native provisioning
failure without that capability and success with the original fixture setting.

Axis2 then passed twelve cases on the original 1.4.1 and 1.6.2 applications,
including eight real Java Meterpreter/command-shell sessions with default Spawn=2.
FTP passed thirteen cases across anonymous read/write, read-only and denied
policies, including PASV/EPSV listing loot and repeated cleanup. These passing
profiles bring cumulative coverage to **53 modules, fifteen families, 186 cases**.
A combined fifteen-family regression subsequently passed; SMTP has a separate
passing result because its profile was added after that invocation began.

SMTP subsequently passed nine cases on four Exim policies, with native recipient
verification and fresh per-message delivery-log evidence. Cumulative passing
profiles now cover **56 modules, sixteen families and 195 cases**. SMTP was not
selected by the already-running fifteen-family invocation and has its own result.

The final cross-check matched every passing result's input SHA-256 against the
current files, with exact example counts, no pending/outside-example errors and
successful teardown. MongoDB is the next family under native qualification;
its definition alone is not included in the verified count.

MongoDB then passed 31 cases across 4.4.30/8.3.11 with authentication enabled
and disabled. Fresh native clients verify enforcement and database-scoped
permissions; module output must match the actual SCRAM hashes, 111 cursor
records and stored nested/empty schema. Verified coverage now totals **60
modules, seventeen families and 226 cases**. Legacy authentication remains a
separate next profile rather than an assumed consequence of these passes.

MongoDB 2.6.12 then exposed two real defects: missing MONGODB-CR hashes and
truncated cursors at 101 records. Separate worktrees reproduced and fixed both;
the combined modern/legacy run passed 43 cases, including stronger permission
and rejected-password negatives. A separate Mongobleed profile passed eleven
cases against open/authenticated vulnerable, fixed, compression-mitigated and
unrelated services, with actual bounded leak loot and independent wire probes.
The cumulative verified checkpoint is **61 modules, nineteen families and 249
cases**. See the [November 9 verification](VERIFICATION-20261109.md) for evidence,
fix commits and qualification limits. SNMP and rsync definitions are currently
under qualification; their presence alone does not add passing coverage.

Rsync subsequently passed six cases on pinned Ubuntu/Debian packages, both
reporting 3.2.7 but independently advertising protocols 31.0 and 32.0. Native
file transfers establish open/protected/hidden-share policy; module tests cover
listing, authentication requirements, optional banner output, an empty daemon
and an unrelated server. Verified coverage is now **62 modules, twenty families
and 255 cases**. SNMP fixes and Linux post-module sessions remain under
qualification and do not add to that count yet.

SNMP then passed its strengthened 22-case parent suite after separate fixes for
leading-dot numeric OIDs and TCP BER framing. Native controls distinguish actual
read/write policy; dual-version scans must return both results, and canonical/
dotted SET paths each run twice with native readback and restoration. Verified
coverage is **65 modules, twenty-one families and 277 cases**. Linux post-module
qualification is continuing; setup/assertion failures there are recorded as
harness issues and do not add passing coverage.

Linux post-module qualification subsequently passed all eight cases across
genuine native command-shell and Meterpreter sessions, with eight fresh
target-side command proofs. Three modules cover actual Docker detection,
normal/specialist/missing command directories and exact configuration-file loot.
The verified checkpoint is **68 modules, twenty-two families and 285 cases**.
CouchDB is under native qualification and is not included yet.

The first CouchDB 3.3.1 suite produced eight cases/three failures after fifteen
independent native requests verified actual users, permissions, documents and
attachment bytes. The configured administrator is omitted from enumeration's
database-list request; valid nonadmin credentials are missed by an admin-only
login probe; unrelated real Apache HTTP-200 fallback is accepted as a login.
Separate worktrees reproduced and fixed login identity, authenticated enumeration
paths and account-creation acknowledgements. The legacy 1.6.1 fixture also
exposed shared option validation converting unchanged defaults into explicit
choices. The corrected owning validator passes 1,169 relevant examples, including
before/after regressions. The final combined modern/legacy parent run passes
all seventeen cases with stable final-source hashes and owned cleanup. Every
registered family is being rerun before updating the aggregate checkpoint;
CouchDB command execution remains separately under qualification.

The shared-validator broad rerun subsequently passed all twenty-four selected
families and 302 cases, with a stronger modern CouchDB rerun independently
checking unrelated HTML on both login endpoints. Current recorded hashes match,
all expected counts match, and owned cleanup passed. The current checkpoint is
**70 modules, twenty-four families and 302 cases**. See the November9 verification
record for exact evidence and per-family durations.

CouchDB command execution has eight successful real session deliveries, but its
new profile remains excluded from passing totals while a configured-administrator
name collision is fixed. Independent native controls confirm account creation HTTP 201
can coexist with session/configuration HTTP 401 for those supplied credentials; the
module currently reports bypass success without usable administrative access.
A separate worktree owns the effective-identity regression/fix. API account,
database and query-server restoration in that fixture is explicit operator
cleanup, not module cleanup. Native2.x, wget, TLS and failed-session cleanup
remain unqualified. Authoritative DNS is the next reusable family under review.

The separate CouchDB exploit fix now verifies effective administrator access
before staging and preserves valid existing-user HTTP 409 access. Original source fails
21 of 33 focused examples; final source passes all 33. Its final parent nine-case
profile passes ten repeated real deliveries, native command ownership, collision
refusal and explicit API restoration, with stable source hashes and owned cleanup.
The current checkpoint is **71 modules, twenty-five families and 311 cases**.
The rejected collision may leave a shadow user requiring administrator cleanup;
credential persistence, CouchDB 2.x, TLS and failed-session cleanup remain limited.

Authoritative DNS subsequently passed 28 cases after independently reproduced
repairs for scalar-host parsing, AXFR/TCP handling, typed record inspection,
amplification accounting and stale update-cache state. The Linux collection
profile passed 12 root/nonroot shell/Meterpreter cases after fixing root cron
loot. Native VNC passed 20 cases over three genuine RFB versions. Apache WebDAV
passed 22 cases after correcting listing requests/parsing and literal file
mutation verification. MQTT passed ten cases after a nil-response parser repair.
Each family has independent target controls, precise assertions and owned cleanup.

The broad revalidation also exposed native-control cleanup and metadata-copy
races. Those setup failures were preserved and classified separately from module
defects. After the metadata snapshot repair, a fresh 26-family invocation passed;
separate source-current SMB, SMTP, WebDAV and MQTT results complete the registered
set. The current verified checkpoint is **83 runtime modules, 30 families and
403 functional cases**, with exact expected counts, zero failures/pending/outside
errors, matching input hashes and successful owned teardown. See the
[follow-up verification](VERIFICATION-20261109-follow-up.md)
for exact evidence, separate fix commits and qualification limits.

The shared Dovecot profile then passed thirteen cases across POP3 authentication
and POP3/IMAP discovery over cleartext and implicit TLS. Independent clients also
prove real mailbox content, credential rejection, TLS-policy refusal and native
STARTTLS access. Initial password-file permission, native-wait and TLS-policy
configuration failures were corrected as fixture issues before module execution.
The checkpoint is now **86 runtime modules, 31 families and 416 functional cases**,
all with current recorded inputs and owned cleanup. Meterpreter CI transport
timeouts have separate isolated diagnosis; the underlying stalls remain
unclassified and the full campaign remains unfinished.

The focused Meterpreter diagnostic selected only the two original examples at
the exact failed CI source. Native controls caught BusyBox rejecting GNU-style
date syntax; the same source with GNU coreutils passed two outer examples and
all eight inner search assertions per example. It did not reproduce the CI hang.
Alpine/LinuxKit and root execution differ from Ubuntu CI. Cleanup hooks returned,
but the final relative deletion returned failure; file removal by that hook is
unproven. The owned diagnostic container and its temporary filesystem were
removed. These cases add no registered production-module coverage. The evidence
and further Ubuntu instrumentation work remain recorded for investigation.

Jenkins is the next family under qualification, with digest-pinned weekly and
LTS vulnerable/fixed pairs, an open controller, and a separate native CLI client
that cannot read the controller fixtures locally. The independent 125-command
native preflight passed after correcting an expectation that rejected a genuine
HTTP 401 challenge without the application version header. The 51-case Framework
matrix covers four modules and remains excluded from passing totals until its
result, actual behavior, recorded inputs and cleanup are checked. Its first full
baseline finished 51 examples/25 failures with matching recorded inputs and
owned teardown. Corrupt CLI frame bytes in file loot, long-path failures, forced
patched-version false content, modern HTML enumeration and script target/cleanup
validation each have concrete native evidence and separate fix worktrees.

The runner is being extended for UDP-only mappings without changing legacy TCP
endpoint shapes. This changes a common recorded input, so the published
`e16b4bc4157` checkpoint remains historical evidence. All qualified families need
fresh current-source results after these changes and Jenkins fixes are integrated;
no new aggregate is claimed from registration or old passing hashes.

The final integrated Jenkins matrix subsequently passed all 51 cases after
three separately reproduced module repairs. All 48 inputs remain current,
native controls and owned teardown pass, and repeated real shell/Meterpreter
sessions have target and cleanup proof. The UDP-aware runner also has a fresh
14-case HTTP pass and a six-case native TFTP pass. The remaining earlier
families are being revalidated before claiming a new aggregate. See the
[Jenkins/UDP qualification record](VERIFICATION-20261109-jenkins-udp.md) for
matched failures, fixes, current evidence and limits. NTP remains separately
under qualification; its setup failures are not classified as module defects.

After the NTP observer's source-path correction, the frozen six-case suite
returned five passes and one verified module failure: an actual unrelated DNS
error packet is reported as an NTP service. Native ntpq and independent wire
controls establish the genuine allowed/refused query policies and unrelated
response. A separate worktree owns reply validation. The additional Jenkins
command scanner is also being investigated in its own worktree using the same
genuine controller images; it is not registered as passing coverage yet.

The NTP correction subsequently passed its matched six native cases and 28
focused examples, preserving real replies and padding while rejecting unrelated
or malformed records. Its owning fix is integrated; a parent native rerun is
pending. The earlier-family rerun has completed eighteen families/222 cases
without failures, with current hashes and cleanup. These remain partial results.
Elasticsearch's real open/authenticated 7.9.1 profile has independent native
data/permission controls and is now running its eleven-case baseline. The latest
published Meterpreter workflow passed, while Verify's OID failure remains red.

The parent NTP family then passed all six cases with current hashes and cleanup,
using warm metadata in 37 seconds. Its shared invocation also contains the
corrected Elasticsearch 11/7 baseline and fails overall. The Elasticsearch
failures now have independent native data/permission evidence after fixing
harness assumptions. Jenkins's additional command scanner has a matched 7/6
to 7/0 repair, integrated locally; its parent suite adds a full-console
Unicode/dollar case and awaits final eight-case validation. The broader
earlier-family rerun continues before a new aggregate is claimed.

That rerun subsequently passed all thirty selected families and 402 cases.
Together with the six separate current-input families, the verified checkpoint
is now **94 production runtime modules, 36 families and 498 functional cases**.
Every selected result has the expected count, zero failures/pending/outside
errors, current recorded input hashes and owned teardown. Jenkins-command's
eight cases include actual-console Unicode/dollar output; Elasticsearch's eleven
cases preserve literal CSV data and handle real permission/zero-hit/unrelated
responses. The [current verification matrix](VERIFICATION-20261109-jenkins-udp.md)
records every selected run and remaining qualification limits. This checkpoint
does not complete the repository-wide goal; most modules still await review.

## WordPress and Tomcat AJP follow-up

The next verified selection covers **98 production runtime modules, 38 families
and 550 functional cases**, with every selected input hash current and owned
teardown passing. WordPress adds three modules/39 cases; Tomcat AJP adds one
module/13 cases. The [verification matrix](VERIFICATION-20261109-wordpress-ajp.md)
records all selected evidence and limits. This does not complete the broader goal.

Native controls caught an Akismet readme-access assumption and WordPress CLI
rewrite setup before classifying production failures. The native-ready parent
WordPress baseline39/11 led to isolated scanner8/1->8/0 and XML-RPC12/10->12/0
repairs; the integrated parent39/0 and relevant unit106/0 pass. Genuine responses
and exact generated-request/native-response proof distinguish endpoint, XML
escaping and REST routing faults from fixture assumptions.

The initial Tomcat13/4 run included one over-specific refusal assertion. After
correcting only that assertion, unchanged source reproduced13/3; the isolated
fix passed13/0 with source-only recorded input differences. Complete large-file
bytes and absence of error-page loot are now asserted, alongside empty, binary,
Unicode and default web.xml reads. Focused captured-frame regressions29/14->29/0
also cover explicitly derived malformed/incomplete responses. The final worker
artifacts were imported unchanged and independently audited against parent bytes;
no redundant identical suite was rerun merely to relabel its provenance.

WordPress administrator upload/session and Multicall paths remain next candidates;
a source hint in Multicall is not yet a verified production-module failure.
Other versions, transport timing, TLS and database persistence remain unqualified.

## November 8 baseline findings

| Family | Functional result | Scope |
|---|---|---|
| Apache HTTP | 14 examples passed | Eight scanner modules; positive/negative cases and Basic authentication |
| Memcached | Four examples passed | One extractor; 1.4.39 cachedump and 1.6.26 crawler, populated/empty cache |
| PostgreSQL | Nine examples passed | Existing protocol suite: sessions, hash extraction, version, file reading and SQL |
| Redis | 17 of 18 examples passed | Four modules; discovery, authentication, extraction/loot and repeated file upload; public-check regression failed |

These are observed functional assertions, not a claim that the entire campaign
or every runner revision passed. Initial development also caught and corrected
fixture-client arguments, loot assertions, config-directory isolation and
runner process-cleanup mistakes. Runs with modified inputs are rejected by the
runner. Final validation after integrating the Redis correction remains required.

### Confirmed Redis file-upload defect

On the baseline, `auxiliary/scanner/redis/file_upload` defines `check` while the
scanner advertises a check only for `check_host`. The console therefore reports
that check is unsupported. Its internal configuration-read check also reports
Vulnerable despite Redis 7 refusing protected snapshot configuration changes.
Real Redis 6.2.14 open/authenticated and Redis 7.2.4 protected/permissive/local
targets reproduced the interface issue. The separate `redis-file-upload-check`
worktree produced focused fix `2f335268630`, with real before/after verification
and 17 focused module examples (24 examples including existing loaded support
specs) passing. The campaign branch incorporates the fix as `28d429e92c0`.
The corrected Redis suite subsequently passed all 18 assertions. The final
stable-input run across all five checkpoint families also passed.

### Apache traversal/RCE batch

The second target batch adds both Apache normalization modules, using 2.4.49,
2.4.50, 2.4.62 and a guarded 2.4.49 configuration. Independent HTTP probes first
confirmed the actual flaw/configuration. All 16 examples passed, including real
file reads/loot and two consecutive command, x86 binary and x64 binary executions
on each affected release. Fresh proof files and temporary-file cleanup were
checked inside the targets. Four negative controls cover fixed code, guarded
configuration and the older CVE encoding on 2.4.50. Initial exploit attempts were
stopped by FileDropper's expected no-session cleanup gate; selecting the payload
first and explicitly setting AllowNoCleanup corrected the test configuration.
Reverse payload sessions and TLS remain untested in this family.

### Investigation queue

- Redis file upload: a fresh Redis 6.2.14 target independently accepted directory
  `/proc` but rejected SAVE there. A real module run left the directory, snapshot
  filename and compression setting changed, plus a generated key. The existing
  sentinel value survived. Separate fixes were integrated as `9ca9bfcb642` and
  `61bf769077f`. The corrected native-query suite verifies state restoration and
  subsequent successful uploads. Real lost-acknowledgement tests also verified
  ownership warnings; unavailable connectivity can still prevent restoration.
- Redis extraction: add bounded-result, binary/large-response and ACL cases.
- Apache HTTP: WebDAV now has a separate passing discovery/write/authentication
  profile. Add TLS, Digest and disabled-TRACE configurations.
- Memcached: add large/fragmented values, key limits and non-loopback loot proof.
- PostgreSQL: extend beyond the first version and privileged role; keep session
  and direct-host paths. Review default credential lists to shorten login work.
- MySQL/MariaDB: both managed targets passed ten cases with strengthened
  account/hash assertions, retaining each implementation's default authentication.
  MySQL 8 credential hash-format metadata and database persistence remain to be
  qualified; an extraction message alone does not prove downstream cracking.
- SSH and Samba: managed fixtures passed. Extend incorrect/key credentials and
  specialist modules. Samba's version detector independently probes dialects;
  its repeated protocol-context case does not prove it honors SMB::ProtocolVersion.
- Tomcat: JSP archive options, Manager target/HTTP401 handling, delayed WAR
  cleanup and executable option forwarding have separate before/after evidence.
  Java session cases now pass with explicit Meterpreter Spawn=0; default Spawn=2
  remains intermittent and unqualified. Deferred WAR cleanup fixed actual
  in-process class-loading failures but did not resolve the default Spawn=2 path.
  Later same-JVM native controls and strace established a separate failure in
  metasploit-payloads 2.0.257: a spawned Java17 launcher writes its inherited
  JDK_JAVA_OPTIONS diagnostic to a pipe the parent already closed, then dies
  with SIGPIPE. A source-backed external candidate passed eight default2
  sessions; it is not integrated or production-qualified. Its thread/loader
  lifecycle and broader compatibility require owning-repository review.
- SQL Server 2022: all 15 cases passed, including independent native hash equality,
  schema results and real session/direct-host queries. Extend authentication,
  restricted roles and version boundaries; this Linux target does not prove
  Windows-specific exploitation. SQL Server 2019 passed the same suite. Axis2
  is the next existing application fixture, with native LFI/login controls.
- LDAP: all ten session/direct-host read cases passed, including LAPS values,
  schema queries and empty shadow-credential/RBCD attributes. The LDAP-only Samba
  fixture does not qualify a complete Windows AD controller, Kerberos, TLS or
  state-changing actions. Its original extra capability is retained for native
  domain provisioning; no host cluster or live directory is used.
- Axis2: login, actual configuration LFI on 1.4.1, rejection on 1.6.2 and Java
  deployment all passed. Both Meterpreter and command-shell deliveries ran twice
  per version with actual command proof and restored files/service registry.
  Native Windows/Linux executable targets, SAP BusinessObjects, TLS and restricted
  accounts remain unqualified. The native target branch currently constructs
  upload contents only for Java; that source observation needs a real regression
  before it is classified as a defect.
- FTP: three modules passed thirteen cases on ProFTPD 1.3.7c. Native controls
  established each permission mode; framework banner normalization is intentional.
  Extend TLS, active-mode data, other servers and credential persistence.
- SMTP: three modules passed nine cases on Exim 4.95, including VRFY, RCPT
  fallback, a catch-all negative, and repeated standard/sixteen-form relay
  detection. Accepted remote test messages are discarded locally by the real
  MTA. This does not qualify external delivery, TLS, SMTP authentication or EXPN.
- MongoDB: four modules passed 31 cases on 4.4.30/8.3.11, including open/authenticated
  services, the buildInfo authentication boundary, exact native SCRAM hashes,
  scoped/incorrect credentials, permission denials, cursor continuation and
  schema loot. MongoDB 2.6.12 adds twelve passing legacy-authentication/cursor
  cases after two separately reproduced fixes. SHA-256-only authentication,
  intermediate versions, TLS, cracking/persistence and old command cursors remain
  unqualified. Mongobleed adds eleven passing checks/scan cases, including
  authenticated-target pre-authentication disclosure; other branches, larger
  scans, forced exploitation and promised secret contents remain unqualified.
- Executable generators: separate owner controls found failures in Mac x86
  explicit Mach-O signing and Linux x86 custom ELF templates. These are deferred
  generator issues, separate from the corrected EncodedPayload argument order;
  ordinary native Tomcat command payloads were verified in the fix worktree.
- Rsync: six cases passed on actual protocol 31.0/32.0 daemons, with independent
  native transfers and authentication controls. Older bare-number greetings,
  SSH transport, host ACLs and persistent reporting remain unqualified.
- SNMP: native controls validate UDP/TCP, v1/v2c and real read/write policy.
  Initial functional failures exposed ordinary leading-dot OID rejection and
  TCP response framing when scanning both versions. Separate fixes are integrated
  and the strengthened parent suite passed all 22 cases. Native long/short BER
  captures underpin framing regressions. SNMPv3, vendor/Windows MIBs, IPv6,
  arbitrary SET data types and credential persistence remain unqualified.
- Linux post modules: three modules passed eight cases over both declared
  session types on native Ubuntu 22.04.5. Setup must wait for the completed
  session event, since registration precedes bootstrap. Actual configuration
  bytes match native reads. Root-only Docker coverage does not qualify other
  distributions, nonroot permissions, other container runtimes or host kernels.
- The isolated Framework console now works with Samba. Extend reverse shell,
  Meterpreter and post-module coverage across declared session types and useful
  delivery families.

WordPress Multicall subsequently passed 22 cases on genuine 4.3.1/4.4/6.8.3
after reproducing and fixing its 4.4 batching boundary and invalid chunk sizes.
Independent native requests distinguish request-scoped authentication protection
from account lockout. The selected checkpoint is **99 runtime modules, 39
families and 572 cases**, with current recorded hashes, exact counts and owned
cleanup. See the [Multicall verification](VERIFICATION-20261109-multicall.md).
The WordPress administrator upload draft remains unqualified: a repeated staged
Meterpreter run reproduces an invalid-session burst despite passing native
controls. A separate permission-check repair does not explain that failure.
Controlled interrupted runs retain diagnostic evidence and no case-count claim.

Linux history/hash collection subsequently passed eight root/nonroot shell and
Meterpreter cases with unchanged production source. Genuine HTTP forwarding and
HTTPS CONNECT controls exposed separate authority-construction and response-body
framing defects; their repairs pass all twelve proxy cases. The integrated
HTTP/WebDAV/WordPress regression passes all 75 cases. The selected checkpoint is
**102 modules, 41 families and 592 cases**, with current recorded inputs, exact
counts and owned cleanup. See the [proxy/history verification](VERIFICATION-20261109-proxy-history.md).
WordPress admin's permission repair and unqualified session reproducer are
retained separately; no session repair is claimed.

Ansible controller collection subsequently passed fourteen genuine root/nonroot
shell and Meterpreter cases. Independent native SSH/Ansible controls separated
five collection defects from target setup: incorrect inventory serialization,
ignored HOSTS, omitted unreachable nodes, compact INI parsing and unreadable key
handling. The owning module and shared Ansible helper have separate repairs.
Joomla API qualification passed twelve cases on authentic 4.2.7/4.2.8 after
repairing its fixed-release boundary and unavailable-version handling. Eleven
additional cases verify PostgreSQL, SSH and HTTP credential persistence directly
through SQL, including repeated reporting, a recovered usable SSH key and
workspace/service relationships. Those three login modules were already counted.
The selected checkpoint is **104 runtime modules, 44 families and 629 cases**,
with current recorded hashes, exact counts and owned cleanup. See the
[Ansible/Joomla/reporting verification](VERIFICATION-20261109-ansible-joomla-reporting.md).
Ansible node deployment, Drupal and JBoss remain separate investigations; native
controls or a focused helper repair alone do not qualify their functional cases.

Consul discovery subsequently passed eleven cases on official 1.20.6/2.0.4
agents, including ACL token acceptance/refusal, public API and UI fallbacks,
repeated discovery, a proxy subpath and unrelated HTTP. An initial console
startup timeout preceded module execution; unchanged selected Consul inputs
passed on retry. No Consul source repair was needed. Independently proven PHP
executable-wrapper variable/scope repairs are integrated, while full Drupal
qualification continues in bounded profiles. The selected checkpoint is
**105 modules, 45 families and 640 cases**; see the
[Consul/PHP verification](VERIFICATION-20261109-consul-php.md).

Drupal's complete matrix subsequently passed as two bounded profiles: nineteen
check/command/native-Linux cases and seven PHP-session cases. All twenty session
executions have fresh command and cleanup proof. The original Drupal module is
unchanged; its shared PHP wrapper repair has separate before/after controls.
Genuine JBoss AS management passed twenty-four cases after repairing nil-database
credential reporting and independently confirming BSH HEAD deployment. HTTP500
alone still does not count as success. The scanner's HEAD500 detection gap and
HEAD cleanup's indeterminate operator output remain explicitly recorded.
The selected checkpoint is **110 modules, 48 families and 690 cases**; see the
[Drupal/JBoss verification](VERIFICATION-20261109-drupal-jboss.md).
Ansible's real slow-command collection boundary is independently reproduced;
its final eight-case timeout repair is still under qualification. Consul
execution, JBoss payload sessions and the WordPress admin reproducer are also
excluded from this checkpoint. Native controls alone add no runtime-module count.

Consul service/rexec execution subsequently passed sixteen cases on genuine
1.20.6 agents with enabled, disabled and ACL-deny policies. Native commands,
API responses and actual filesystem/state observations distinguish successful
execution from a zero-exit CLI with no acknowledgements. The native-passing
baseline had one real module failure: a rejected rexec session creation left a
nil value that was dereferenced. A separate owning repair now classifies denied,
unreachable and malformed creation replies before another request. All original
functional assertions pass afterward. The selected checkpoint is **112 modules,
49 families and 706 cases**; see the
[Consul execution verification](VERIFICATION-20261109-consul-execution.md).
Ansible's bounded shell/Meterpreter profiles, JBoss's session-only compiler
configuration and Linux credential-file collections remain active separate work.

JBoss Java deployment subsequently passed twelve strict cases, opening sixteen
actual Meterpreter/command-shell sessions with default Spawn=2. Both original
automatic-target failures came from the vendor JSP compiler on Java 8; the
session-only fixture now uses documented Ant/javac configuration while native
hashes prove the vendor code unchanged. Every positive path repeats with fresh
command proof and exact deployment restoration. The selected checkpoint is
**114 modules, 50 families and 718 cases**; see the
[JBoss session verification](VERIFICATION-20261109-jboss-sessions.md).
Ansible deployment and Linux credential-file collection continue separately.

Linux credential collection subsequently passed two six-case profiles covering
SSH through shell/Meterpreter and Docker/RubyGems through their declared shell
sessions. Real client-produced files, native authentication and direct SQL
separated three owning defects from target setup. Recovered values pass sixteen
SSH, eight Registry and eight private-gem authentications; exact loot, permission,
empty/missing and repeat checks pass. Separate source repairs preserve spaced
home paths/account names, complete Docker passwords and exact RubyGems keys.
The selected checkpoint is **117 modules, 52 families and 730 cases**; see the
[credential-file verification](VERIFICATION-20261109-credential-files.md).
Ansible deployment, Erlang execution and WordPress admin remain unqualified.

Etcd subsequently passed sixteen cases on official 3.4.35/3.5.18 targets with
native v2 authentication, disabled v2 alongside working v3, an empty store,
proxy paths and unrelated Apache JSON. Native controls separated unordered
directory reads from confirmed module defects. Owning repairs preserve valid
JSON loot, reject unrelated documents, supply native Basic auth and handle
negative replies without missing-method exceptions. All 26 module executions
pass, including ten exact-loot comparisons with unchanged native keys. The
selected checkpoint is **119 modules, 53 families and 746 cases**; see the
[etcd verification](VERIFICATION-20261109-etcd.md).
Ansible/Erlang execution and WordPress admin remain unqualified; genuine Solr
delivery is under separate native preparation.

Ansible node deployment is now deferred with a checksum-verified diagnostic
checkpoint. Raw split-profile green counters were rejected after a positive
operator abort; a final redirected native comparison does not explain the
ordinary markerless call. No experimental module or shared-helper repair is
integrated. See [the deferred finding](DEFERRED.md#ansible-node-deployment).

ZooKeeper subsequently passed eight normal version/permission cases, while a
genuine sliced TCP profile exposed silent environment truncation. Native EOF
reads recover all eighteen fields within the module's timeout; the original
module saves only the first six. The owning stream-read repair passes the
unchanged sliced case twice and all eight normal cases. Current recorded
inputs, exact counts and owned teardown establish **120 runtime modules,
55 families and 755 functional cases**. The
[verification record](VERIFICATION-20261109-zookeeper.md) retains the original
passing narrow profile, failed transport profile and both repaired results.

Kubernetes then qualified enumeration and all four pod-execution delivery
targets against a genuine isolated K3s/containerd cluster. Native projected-token
and certificate-verified API controls expose two modules discarding a namespace
already discovered from a real Meterpreter session. Five owning calls now use
the existing accessor; nine shared API helpers remain unchanged. Final twenty-five
cases pass with exact loot, fresh pod/session proofs, repeated state restoration,
current inputs and owned teardown. Coverage reaches **122 runtime modules,
57 families and 780 functional cases**; the
[verification record](VERIFICATION-20261109-kubernetes.md) documents its privileged
nested-runtime isolation and inherited lint limitations.

RabbitMQ/Erlang then adds twenty-nine strict cases with real AMQP messages,
verified TLS, credential/reporting assertions and eight fresh shell/Meterpreter
sessions. Native controls distinguish Erlang framing/authentication, concurrent
RPC completion and session-triggered socket closure; separate owning repairs
restore exact repeated state. A vendor health-CLI ownership replay supports
the separate broker fixture correction, followed by a fresh combined pass.
Current counts, input hashes and owned teardown establish **125 runtime modules,
59 families and 809 functional cases**. The
[verification record](VERIFICATION-20261109-rabbitmq-erlang.md) retains every
baseline, native/derived distinction and explicit platform limit. Grafana, Solr,
Prometheus and ActiveMQ continue separately.

Grafana subsequently qualifies twenty-three cases against eight actual branch
releases plus a subpath installation and unrelated Apache. Setup failures for
wordlist paths and console startup are retained separately from nine original
unsupported checks and observed false vulnerability messages on fixed releases.
Separate owning repairs implement the scanner interface and exclusive fixed
upper bounds; all final checks and exact repeated collection pass. Coverage is
**126 runtime modules, 60 families and 832 functional cases**, with current
recorded inputs and owned teardown. The
[verification record](VERIFICATION-20261109-grafana.md) retains full failure
classification, assertion strengthening and two inherited lint limitations.

Solr then qualifies twenty-eight cases across three bounded profiles. Native
controls prove the actual affected/fixed/default-ineligible deployments before
classifying shell-variable macro corruption and omitted parent cleanup. Separate
owning repairs pass eight exact command proofs and sixteen used sessions. A
pooled-listener assumption and self-deleting download/copy race are corrected
with native evidence; all profiles are replayed after the common fixture changes.
Current counts/hashes/teardown establish **129 runtime modules, 63 families and
860 functional cases**. The [verification record](VERIFICATION-20261110-solr.md)
retains every phase, resource-lifetime limitation and inherited lint findings.

Prometheus subsequently qualifies eighteen cases with sixty-five independent
native controls and seven genuinely healthy scrape targets. Original failures
separate explicit DNS ports, adjacent static credentials and quoted metric labels
from a pre-prompt setup timeout. A shared-helper repair passes fifty focused
examples and all final exact-loot/repeat cases; both module sources remain
unchanged. Current inputs and owned teardown establish **131 runtime modules,
64 families and 878 functional cases**. The
[verification record](VERIFICATION-20261110-prometheus.md) distinguishes actual
redaction/references from plaintext credentials and records platform/provider
limits. Shared Fetch lifecycle, ActiveMQ and capture-protocol work continues.

ActiveMQ OpenWire then qualifies fourteen cases on actual Apache affected/fixed
brokers. Independent native JMS and process-parent proofs distinguish incorrect
payload choices and pooled-listener assumptions from an early XML-resource
cleanup defect. The owning callback-lifetime repair passes all fourteen cases,
including eight used sessions and repeated exact file/state restoration. Current
inputs and owned teardown establish **132 runtime modules, 65 families and
892 functional cases**; see the [verification record](VERIFICATION-20261110-activemq.md).
A separate existing CI short-name fixture is corrected using native OpenSSL
registry evidence, without changing certificate behavior. Shared Fetch ownership,
Jolokia, capture protocols and Docker Engine continue separately.

Shared Fetch ownership then passes native before/after controls and all 42
Solr/OpenWire consumer cases with sixteen plus eight used sessions. Cleanup now
releases the caller reference and stale route ownership while preserving another
owner. Final listeners genuinely refuse connections. A separate OpenWire retry
count mistake is corrected to a real bounded deadline after both files are
independently observed disappearing. See the
[Fetch record](VERIFICATION-20261110-fetch-lifecycle.md); coverage count remains 132.

Docker Engine then adds ten cases on two real nested daemons and Basic/TLS
gateways. Native controls and actual SQL separate a legacy host-model fixture
expectation from a confirmed unrelated HTML/200 false detection. The owning
validation repair passes 21 focused examples and all ten final cases. Current
recorded inputs and owned teardown establish **133 runtime modules, 66 families
and 902 functional cases**; see the
[verification record](VERIFICATION-20261110-docker-engine.md). Capture's 30-case
result is retained while an independent IMAP parser regression/completion
follow-up is resolved before its publication; Flink/Jolokia remain in progress.

Capture protocols then qualify 32 cases across six actual Framework servers and
genuine libcurl/libpq/Python clients. Native target controls distinguish fixture
assumptions from password/authorization/Startup/DATA parsing defects. Independent
review catches a legal closing-brace regression before publication; separate
parser and response-flow repairs pass 50 focused examples and the full 32-case
replay. Exact wire and SQL retain UNTRIED semantics, and real IMAP clients finish
with deliberate refusal instead of timeout. Both the unchanged initial seal and
additive follow-up remain available in the
[capture record](VERIFICATION-20261110-capture.md).

Flink adds 24 cases across traversal and real Java execution. Native controls
identify container PID1 zombie retention and disabled-submit multipart staging
as fixture/target behavior; strict actual payload process equality and explicit
operator staging restoration remain required. A narrow owning TARGETURI option
repair passes 6 focused examples. See the
[Flink record](VERIFICATION-20261110-flink.md).

Jolokia adds 18 cases against genuine affected/fixed ActiveMQ. The owning repair
uses authenticated Origin-aware broker discovery and positive state receipts,
refuses an existing NC before mutation, and preserves a real TCP bridge. Both
matched and stricter warning-gate replays pass with six used sessions and
confirmed owning cleanup; parent tests pass 48 examples. Current recorded inputs,
exact counts and owned teardown establish **142 runtime modules, 71 families and
976 functional cases**. See the [Jolokia record](VERIFICATION-20261110-jolokia.md)
and [integrated checkpoint](VERIFICATION-20261110-capture.md). WordPress and
Ansible remain unqualified in the [deferred index](DEFERRED.md). NFS, legacy
ActiveMQ and additional database capture qualification continue separately.

The [NFS/reader checkpoint](VERIFICATION-20261110-nfs-reader.md) now establishes
**145 runtime modules, 73 families and 1,002 functional cases**. NFS adds two
scanners and 18 cases after native access and official source prove the exact
UNFS3 unrestricted-export marker. Parent documentation-only comments are tested
in a fresh 18/0 replay. The ActiveMQ source reader adds eight cases after exact
stock JSP/native response comparisons separate a URI fixture mistake from
actual source-selection and HTTP 200 false-positive defects. Parent focused
tests pass 20/0 and 22/0. The prior fork Verify collection failure is independently
reproduced and repaired with a Flink profile default; a fresh 15/0 plus 9/0
replay and acceptance-excluded discovery pass. Historical evidence remains
unchanged. Database capture, legacy FileServer, SIP and Gitea continue in
separate worktrees; the full campaign remains incomplete.

The [database capture checkpoint](VERIFICATION-20261110-database-capture.md)
establishes **147 runtime modules, 75 families and 1,031 functional cases**.
Seventeen MySQL and twelve MSSQL cases pass against genuine clients after three
owning source commits. Exact native wire and direct SQL verify 25 complete
UNTRIED credential graphs and 36 John lines. Original owner failures remain
separate from passive-job and joined-row observation corrections. The parent
passes 77 focused examples, six-file lint and excluded acceptance discovery,
checks all current inputs and independently verifies the 3,296-entry worker seal.
FileServer, SIP and Gitea continue; unqualified WordPress/Ansible investigations
remain retained.

The [FileServer checkpoint](VERIFICATION-20261110-fileserver.md) establishes
**148 runtime modules, 76 families and 1,040 functional cases**. Nine genuine
ActiveMQ cases and twelve used sessions pass after separate owning URI,
classloader and cleanup-option repairs. Mixed original failures remain separate
from native-proven environment and JAR-cache causes; an isolated 9/1 run proves
the false-option defect before its guard-only repair. Both false-option runs
preserve uploads before explicit operator restoration. Parent 20/0, four-file
lint, excluded discovery and all 62 current inputs pass, and the 788-entry worker
seal is independently checked. The prior published 147-module revision passes
all 14 fork Verify jobs; that result is not inferred for later revisions.
SIP/Gitea fixture corrections, NiFi scanner qualification and a stock Java8
Tomcat default-spawn matrix remain in progress.

The [NiFi scanner checkpoint](VERIFICATION-20261110-nifi.md) establishes
**150 runtime modules, 77 families and 1,055 functional cases**. Both original
production scanners remain unchanged. Fifteen cases/31 actual runs pass with
native versions/authentication and exact successful SQL reporting/workspace
isolation. An initial readiness miss and three expected-negative helper failures
are retained as fixture issues; the current 55 inputs and all owned teardown
pass. The 535-entry worker export and all source/import checks are independently
verified. Remaining NiFi execution/gathering, Gitea, SIP and the stock Java8
Tomcat default-spawn matrix continue separately.

## Remaining work

- Review existing protocol suites and supply reusable managed containers.
- Review container hints across module documentation and reuse viable labs.
- Expand through reusable network service and web application families.
- Review post modules using suitable real sessions and cover declared types.
- Review other module categories and record justified exclusions individually.
- Twelve source-hashed reviews now identify separate Linux-kernel/container-host,
  macOS, Windows, Xerox, Cisco and AWS control-plane requirements in `reviews.yml`; these do not
  establish universal infeasibility. Kubernetes now has a genuine isolated
  nested-runtime lab; other OS/device requirements still need individual targets.
- The four AWS reviews cover their actual EC2, IAM and SSM operations; they do
  not exclude S3-compatible services. Alternate endpoints or API emulators alone
  do not prove an AWS guest launch or SSM session. No cloud resources are created.
- Investigate failures with target evidence before classifying module defects.
- Repeat meaningful state-changing paths and retain concise evidence summaries.

This is a campaign record, not a claim that the repository-wide goal is complete.

## Stock Tomcat Java8 default qualification

The [current checkpoint](VERIFICATION-20261110-tomcat-defaults.md) qualifies150
runtime modules,78 families and1,069 cases. The fourteen new Java8 cases use
default Spawn2; a fresh fourteen-case Java17 explicit-Spawn0 replay keeps the
shared spec's older profile current. Both have twelve used sessions, matching
input hashes and owned cleanup. Native controls preserve the stock Java17
default-spawn failure rather than relabelling it as repaired. No production,
SDK, runner or timeout change is needed for the bounded Java8 profile.

## Genuine Gitea execution checkpoint

The [current checkpoint](VERIFICATION-20261110-gitea.md) qualifies152runtime
modules,80families and1,097cases. Two fourteen-case Gitea profiles retain matched
original/final evidence, native API/UI/migration controls, twelve used sessions
and36exact restoration receipts. Three separate owning repairs address rotated
cookies/prefixed paths/branded404 detection, migration href joining and cleanup
after policy refusal. Parent focused tests pass27/0; current hashes and exact
resource absence pass. Documented Windows/multicommand/same-instance and other
qualification gaps remain open rather than counted as coverage.

## Hadoop YARN native qualification

The [current checkpoint](VERIFICATION-20261110-hadoop.md) qualifies153runtime
modules,82families and1,116cases. Hadoop's original owner passes19cases after
verified GNU-which, handler lifetime, payload-option and DNS-label fixture
corrections. Native real jobs precede26 public calls and six used sessions;
current maps and all134 parent resource checks pass. YARN retries imply
at-least-once execution; exact19 TARGETURI warnings and explicit operator
application/file restoration remain visible limits. No production repair.

## NiFi processor qualification

The [NiFi processor checkpoint](VERIFICATION-20261110-nifi-processor.md) qualifies
154 runtime modules, 85 families and 1,135 cases. The original processor owner
passes 19 cases on three real stock releases, with ten used shells, real bearer
policy, exact graph/canary restoration and current recorded inputs. Fixture
observer/parser/compatibility corrections are separate from module defects.
Linux Fetch rejection, local self-signed TLS and the early native identity
evidence gap are retained explicitly. No production or shared code change.

## SIP qualification

The [SIP checkpoint](VERIFICATION-20261110-sip.md) qualifies161 runtime
modules,89families and1,177cases. Seven modules pass42 real Asterisk/client cases
after separately reproduced source repairs. Native John interoperability corrects
both an invalid initial oracle and real captured URI/format/reporting defects.
Parent41 examples,94 current inputs, all295 resource checks and exact inherited
lint/docs comparisons pass. TLS trust, legacy deregistration policy and seven
other individual endpoint requirements remain explicit.

## Spark qualification

The [Spark checkpoint](VERIFICATION-20261110-spark.md) qualifies163 runtime
modules,91families and1,204cases. Two genuine profiles pass27cases and ten used
sessions after an actual raw-vs-encoded form counterfactual and source-only
regression establish the plus-byte defect. Corrected Apache advisory coverage
includes affected3.1.3. Parent72 current inputs, all168 resource checks, focused
regressions and exact inherited static limits pass. REST undeclared option and
passive-job semantics remain explicit; the full campaign continues.

## InfluxDB qualification

The [InfluxDB checkpoint](VERIFICATION-20261110-influxdb.md) qualifies164 runtime
modules,92families and1,220cases. InfluxDB original source passes16cases with32
public calls,18exact JSON loot documents and16native state audits. A native CLI
precision mismatch and a shared-client refusal-message fixture expectation are
corrected before qualification, with original evidence preserved. Parent39 current
inputs and all38 resource checks pass; an early aggregate-log preservation gap
and1.x query/auth/path limits remain explicit. No production repair.

## NiFi H2 qualification

The [NiFi H2 checkpoint](VERIFICATION-20261110-nifi-h2.md) qualifies165 runtime
modules,95families and1,233cases. H2 adds13 cases after separately reproduced
DTO/cleanup/shared-state repairs; scanner15 and processor19 remain current after
requalification. All47 selected cases pass across two identified invocations.
Native two-versus-thirty-second controls correct the legacy quick-command fixture
without a timeout/source workaround. Parent37 focused examples,120 current input
hashes,2,805 worker manifest entries and187 exact object checks pass. Used-shell,
operator-file-cleanup, original/mixed failures and inherited lint limits remain
explicit; the campaign continues.

## SMB directory qualification

The [current checkpoint](VERIFICATION-20261110-smb-directory.md) qualifies 168
runtime modules, 98 families and 1,265 cases. Three modules pass 32 current cases across
three explicitly identified invocations after native-proven Unicode/null-pointer/
session-port/whole-write repairs. Binary observer and stdout/stderr corrections
are retained separately from source defects. Parent 46 focused examples, 96 current
inputs, 2,587 worker checksum entries and 147 cleanup checks pass. The campaign now
uses one project and at most five test containers; larger profiles are queued,
not declared infeasible. Windows/AD and the first unrecorded volume-ID limit remain
explicit. The full campaign continues.

## NiFi credential collection qualification

The [current checkpoint](VERIFICATION-20261110-nifi-credentials.md) qualifies 169
runtime modules, 99 families and 1,276 cases. NiFi credential gathering passes 11
cases after capture-backed JSON, keystore association, reporting and partial-file
repairs. All 22 public calls, 11 used sessions, exact decrypted loot, repeat-stable
SQL records and owned teardown pass. Parent 26 focused examples, four-file lint,
73 current inputs and 16 cleanup checks pass. Thirteen source-hashed feasibility
reviews now include the Windows-specific ActiveMQ traversal requirements; Linux
ActiveMQ coverage does not qualify that pathname behavior.

At the user's explicit request, all 31 unrelated containers (14 running and 17
nonrunning) were removed after NiFi teardown, preserving images and volumes.
Docker was empty before the next serial Druid run. Only campaign containers may
run, with the existing five-container limit. The full campaign remains incomplete.

## Druid compact qualification

The [current checkpoint](VERIFICATION-20261110-druid-compact.md) qualifies171 runtime
modules,103 families and1,310 cases. Two Druid modules pass34 cases: preserved
JNDI/session19 plus compact JS15. Source-only argument encoding and current JNDI
delivery repairs reproduce22/9 to22/0; a separate observer visibility correction
reproduces26/2 to26/0. Failed original/compact attempts remain preserved. Compact
projects use five containers with actual2208MiB/2.35CPU ceilings and strict actual
socket-write/native-command proofs. The earlier larger JNDI/session profiles remain
historical passes and require redesign before local replay under this budget.

Parent103 qualified input hashes, all367 imported files and299 exact resource
absences plus two temporary aliases pass. Ten new Ruby files lint cleanly; four
inherited source findings and five docs warnings/one INFO remain explicit.
Original human Scenarios and every existing documentation byte remain unchanged.
Only campaign containers may run; serial execution and teardown continue.

## OpenTSDB qualification

The [current checkpoint](VERIFICATION-20261110-opentsdb.md) qualifies173 runtime
modules,107 families and1,359 cases. Both original OpenTSDB owners pass49 cases
with98 public operations and12 actual used sessions. The original49/20 diagnostic
mixed native producer, Basic negotiation, compatibility and weak forced-negative
fixtures; corrected independent controls and stricter assertions establish49/0
without production repairs. Parent87 current inputs,235 imported files, Ruby
lint, dry19/6/18/6 and32 cleanup checks pass. Six inherited docs warnings and
explicit operator-file cleanup remain documented. All earlier native/failure
records are preserved; the full campaign continues.

## Gogs hook qualification

The [current checkpoint](VERIFICATION-20261110-gogs-hooks.md) qualifies 174
runtime modules, 108 families and 1,369 cases. Gogs hooks reproduce ten cases
with five original failures and then ten passes after owning path, branded-404
check and non-session commit/cleanup repairs. Independent native controls and
two payload calibrations precede the four used owning sessions. Parent 22
focused examples, 60 current inputs, 134 imported files and 1,774 export entries
pass; all nine owned objects and project labels are absent after teardown.
The original assertions, options, helper, target configuration and deadlines
remain unchanged. Inherited source/docs findings and nonfatal avatar warnings
are documented. Rebase/fixed-rebase's fifteen prepared cases remain unrun.
At this checkpoint, 37 unrelated containers have been removed at the user's
request, including six tool connectors that reappeared; their images and volumes
were preserved. New labs continue one project at a time within five containers.

## GeoServer qualification

The [current checkpoint](VERIFICATION-20261110-geoserver.md) qualifies 176 runtime
modules, 111 families and 1,379 cases. Two unchanged GeoServer owners pass ten
cases across 2.25.1, 2.25.2 and 2.25.6. Native controls establish the separate RCE
and XXE fixes; four actual commands and four exact loot files prove positive
module paths. The original ten/three result is preserved: anonymous About pages
hide version data, so corrected tests require Unknown and default AutoCheck
blocking, then explicitly exercise the supported override. No production repair
or weakened command/file proof produces the pass.

The parent passes six recorder examples, four-file Ruby lint, both module-doc
checks, all 51 current inputs, all 145 imported files and the 286-entry final
export. All nine containers, six networks and three volumes are absent, with
nine empty project-label queries and an empty global container inventory.
Sessions, fetch delivery, Windows, built-in roles and other data combinations
remain pending. The one-project/five-container cap remains in effect.

After GeoServer, four unrelated AWS/GitHub MCP tool containers reappeared during
the Grafana follow-up. Their exact IDs were removed at 17:27:54 UTC, preserving
images and volumes; cumulative unrelated removals are 41. The cause of their
recreation is unproven. A bounded, task-local host check now removes only these
known unlabeled tool images and skips Compose-owned targets. Global MCP settings
and the reusable runner's refusal of unrelated containers remain unchanged.
The Grafana follow-up's 14/four console-fixture result and all exact owned
teardown checks are retained in [deferred investigations](DEFERRED.md); no new
module or functional case is added to the 176/111/1,379 checkpoint.

## Grafana SQL expression qualification

The [current checkpoint](VERIFICATION-20261110-grafana-expression.md) qualifies
177 runtime modules, 115 families and 1,393 functional cases. Fourteen Grafana
cases pass across Viewer, Anonymous Viewer/subpath, independent fixed and
missing-binary profiles. Four owning Bash sessions and four exact quoted command
outputs are proven; two independent real payload/handler calibrations precede
owning calls. Target exit/native PID absence precede host session close.

The module-local byte-string repair corrects an actual UTF-8 Content-Length
defect. Foreground dispatch and failed copied-file calibration remain preserved
fixture failures; 11.0.5 SELECT-only RCE remains separately unqualified. All 82
inputs are current; parent 233 imported files, 362 export entries, lint/docs and
29 cleanup queries pass. Positive RCE scope remains 11.0.0 and selected
command/session paths. Three additional auto-recreated tool containers were
removed by the bounded task-local guard, bringing observed unrelated removals
to 44. Only the active test project may run, within the five-container limit.

## Gogs new-repository rebase qualification

The [current checkpoint](VERIFICATION-20261110-gogs-rebase.md) qualifies
178 runtime modules, 116 families and 1,398 cases. Hooks requalify ten cases;
Gogs 0.14.2 new-repository rebase passes five cases with two repetitions each,
including exact commands, used Bash sessions, quota/password refusals and the
real subpath. A separately verified one-option repair registers TARGETURI.
Actual default-workspace SQL and typed reporting replace earlier invalid row
counts and an unset-workspace baseline.

Existing-repository five/three and fixed-release five/one remain whole-family
unqualified. The new closed-PR observer assumes a numeric tab suffix absent
from actual pages, and the missing-path oracle expects an unrelated-product
reason for a branded patched-version404. These are retained observer failures;
the unexecuted ref/parent/feature gates and failed families add no qualification.
All 81 selected inputs, 277 imported files and 754 export entries verify.
Parent 52 fresh queries confirm eighteen containers, four networks, seventeen
volumes, twelve label inventories and global containers absent. One-project/
five-container limits remain, with 44 unrelated removals observed in total.

## Gogs existing-repository and fixed-release qualification

The [current checkpoint](VERIFICATION-20261110-gogs-repositories.md) qualifies
178 runtime modules, 118 families and 1,408 cases. A fresh complete Gogs invocation
passes 10/0 + 5/0 + 5/0 + 5/0 against the corrected closed-PR and branded404 observers.
All original repository-state gates remain; six repeated closed-PR proofs reach
canonical ref, seed-parent, feature-content and object checks. Eight owning
sessions are used and five native calibrations complete. Exact raw404 identity,
Safe reason and typed reporting state pass on fixed 0.14.3.

The parent verifies 81 current inputs, 276 whole-invocation files and 528 immutable
export entries. All four actual result/RSpec records and the summary complete;
the aggregate manager's exit code was not directly observed after continuation.
The 52 fresh terminal queries prove eighteen containers, four networks and
seventeen volumes absent,
empty labels and an empty global inventory. Current host cleanup also removes
recreated unrelated tool containers; observed removals reach 58. No images or
unrelated volumes are pruned. One project runs at a time within five containers.
Windows, other architectures, same-instance reset and unchanged-existing-repo
repeatability remain pending; earlier failures remain immutable.

## Flowise open and Basic qualification

The [checkpoint at that stage](VERIFICATION-20261110-flowise-open-basic.md) qualifies
180 runtime modules, 120 families and 1,412 cases. The frozen six-profile run
finishes naturally with 3/0, 1/0, 3/3, 2/2, 2/1 and 1/1; all teardown passes.
Only open/Basic profiles qualify. JWT/reset stops at native replay status500
versus expected400; npx uses its first owning shell and proves remote process
exit before a host-registry observer timeout; fixed npx stops at private package
manifest resolution. Those profiles remain unqualified and their failures are
preserved for separate fixture investigations.

The parent verifies 102 current inputs, all 365 invocation files and 483 immutable
export entries. Focused 47 examples, seven-file lint and four module-doc checks
pass. The first actual prompt/BOOT and fresh atomic metadata snapshots are
observed live. After natural termination, 61 fresh queries verify exact
22-container/12-network/8-volume absence, empty project labels and global
inventory. One project runs at a time, capped at three/four containers for these
profiles. Observed unrelated container removals reach 60; images and unrelated
volumes are preserved. The campaign remains active and incomplete.

## Flowise recovery, sessions and fixed releases

The [current checkpoint](VERIFICATION-20261111-flowise-recovery-sessions.md)
qualifies 182 runtime modules, 124 families and 1,420 cases. A fresh unchanged
invocation at reviewed worker revision `edbba171de8` naturally exits zero: 3/0,1/0,3/0,2/0,2/0,1/0.
Repeated takeover and legitimate mail recovery, complete consumed-token row and
distinct-password proof, JWT/Basic refusals, six used owning sessions and fixed
release negatives all pass. Three native calibrations remain separate evidence.
Private exports, stdin transport and shell bootstrap/host closure are fixture
corrections; production owners, core, runner and human Scenarios are unchanged.

The parent verifies all 102 inputs, 475 whole imported files including eight
hidden/cache files, and 599 immutable entries. First cold prompt/BOOT and fresh
atomic metadata are observed live. All 61 fresh checks of 22 exact container IDs, 12 networks,
8 volumes and label/global absence queries pass. One project runs at a time,
with three/four capped containers. Earlier 483/557-entry failures remain
unchanged. The previous public CI head has a cancelled Mettle job with repeated
send timeouts; cause remains unclassified. Other listed Flowise paths and the
broader module inventory remain incomplete.

## MinIO source builds, JSON loot and session collection

The [MinIO checkpoint](VERIFICATION-20261111-minio.md) qualifies 184 modules,
126 lab profiles and 1,429 examples. Dedicated source-build/assembly/native/
functional commands keep MinIO reproducible in the repository; static inventory
metadata exposes its profiles alongside ordinary manifest-backed labs.
The real public compiler wrapper passes, and final affected/fixed profiles pass
6/0 and 3/0. Four real module-derived S3 cycles, exact JSON/Untried SQL reporting,
workspace/repeat checks, two used Linux session types and all fourteen client
states/22 post calls complete with restoration. The original Hash-as-JSON defect
is corrected by a one-line serialization change. Earlier failures and a
600-second fixture timeout remain immutable, rather than being counted as passes.

Parent 101 focused checks and twelve-file lint pass. Complete 557/171-file runs
and 841/439-entry exports verify. Integration preserves a newer Gogs-only helper;
guarded namespace/discovery probes establish that it is not included by MinIO,
while all other 238 selected inputs match. Each profile has sixteen fresh exact
cleanup queries. One project runs at a time within five containers, 1,600 MiB
and 2.35 CPUs; global containers are empty after teardown. Other declared OS/
session types remain pending. The campaign remains active and incomplete.

The prior published head's PHP 5.3/macOS CI failure is retained separately.
Its UDP receive EAGAIN is not proof of wrong peer data; source investigation
reproduces an existing two-frame transport defect, but exact CI attribution is
unproven. No incompatible IO capability removal is merged.

## Superset cookie native controls and owner repairs

The [current checkpoint](VERIFICATION-20261111-superset.md) qualifies 186 modules,
127 profiles and 1,443 functional examples. The fourteen-case Superset 2.0.0 lab
passes with genuine installed-source/cookie/identity controls and exact logical
state preservation before and after owner calls. Actual SQL graphs and repeat
IDs establish credential reporting; a native-proven anonymous-cookie path also
works after a rejected password. Explicit JSON signing produces an accepted
administrator identity while the legacy String default stays unchanged.

Separate worktrees repair JSON session support and hostname reporting; 28
focused unit cases pass after parent integration. Original native/setup/control
and owner failures remain sealed. Parent verifies all 57 selected inputs, all
74 imported run files, the 135-entry final seal, fresh actual BOOT/atomic
metadata, and twelve exact 4/2/2 cleanup queries with empty global containers.
The four-container profile caps memory at 2,144 MiB and CPUs at 2.15. Its dedicated
launcher verifies gateway network identities; shared batch selection, broader
versions and SQL Lab/permalink/RCE session paths remain separate work.


## Ray jobs, payload architectures and resource bounds

The [Ray checkpoint](VERIFICATION-20261111-ray-jobs.md) qualifies 188 modules,
132 profiles and 1,476 examples. Genuine Ray 2.6.3 covers command execution,
head/agent routes, AutoCheck, x64/x86/AArch64 payload paths and repeated live
sessions. Independent calibrations precede owner calls. Both file-read versions
were refreshed after a bounded diagnostic correction; the confined 2.8.1 owner
profile passed after increasing only its memory budget, with its monitor enabled.
Root preserves original native/harness failures, whole-run bytes, current selected
inputs, cold metadata evidence and exact cleanup audits. CPU/log owners, other
releases and the startup-watchdog cause remain pending. No PR is created.


## Ray CPU profile owner

The [CPU profile checkpoint](VERIFICATION-20261111-ray-profiler.md) qualifies
189 modules, 134 profiles and 1,488 examples. The unchanged owner passes checks,
command paths, AutoCheck, unrelated negatives and repeated x64/x86/AArch64
sessions on real Ray 2.6.3. Native controls distinguish ordinary py-spy permission
denial from successful same-user command substitution; HTTP 500 alone does not
prove the injection failed. Seven independent calibrations and fourteen owning
sessions pass. Root verifies 88/96 current inputs, whole 135/79-file imports,
fresh cold metadata and exact cleanup. Ordinary profiling with additional
privileges, newer versions and the modern log owner remain separately pending.


## Modern Ray log path enumeration

The [modern log checkpoint](VERIFICATION-20261111-ray-modern-logs.md) qualifies
190 modules, 135 profiles and 1,499 examples. A pinned full Ray 2.56.0 deployment
passes native source/core/SDK/HTTP controls and eleven real module/loot cases.
Five native resource/probe failures remain sealed, followed by a complete native
baseline and two passing owner runs. The final 68.947202-second suite writes
fourteen exact new loot files. Root verifies all 48 current inputs, a whole
79-file import, actual cold metadata, three-role resource limits and nine exact
cleanup queries. Enumeration does not establish arbitrary file-content retrieval;
one genuine node and this exact image are qualified. The fixed comparison and
multi-node grouping still need their own main-path evidence. No PR is created.

## Ray log API fixed-release boundary

The [fixed log comparison](VERIFICATION-20261111-ray-fixed-logs.md) advances the
checkpoint to 190 modules, 136 profiles and 1,506 examples. The affected owner
replays eleven cases, and the fixed 2.57.0 owner passes seven cases, including
forced denials and exact ordinary-log loot. Native controls require precise
gRPC rejections and correlated server errors behind generic HTTP 500 responses.
Two initial identity/probe failures remain sealed. Root verifies 54 current
inputs, the unchanged 139-file import, cold/cache provenance and seventeen exact
cleanup queries. Multi-node and remaining valuable modules still need coverage.

## Memcached UDP scanners

The [UDP checkpoint](VERIFICATION-20261111-memcached-udp.md) qualifies two more
modules, reaching 192 modules, 137 profiles and 1,516 examples. Genuine 1.4.39
and 1.6.26 targets pass native protocol checks and ten owner cases. Twenty unique
call records prove actual versions, single/multi-packet stats, exact amplification,
reporting API arguments, closed/disabled negatives and repeated batches. Two
setup/harness failures remain sealed; no production fix is needed. All 38 inputs
match current source, cold metadata is observed and ten root cleanup queries
pass. The four-container budget is 960 MiB/1.3 CPUs. Registration covers 194
sources; the broader feasible-module campaign remains incomplete. No PR is created.

## FTP bounce port scanning

The [FTP bounce checkpoint](VERIFICATION-20261111-ftp-bounce.md) qualifies the
unchanged module on genuine ProFTPD 1.3.7c, reaching 193 modules, 138 profiles and
1,526 examples. Native active transfers and real destination logs support ten
cases, twenty owning calls and eighteen actual received data connections. Auth,
relay policy, low/closed ports, lists/ranges and repeats pass. A native-log-field
matcher failure remains sealed. Root verifies all 43 inputs, actual cold metadata
and ten exact cleanup queries. Four containers remain capped at 960 MiB/1.3 CPUs.
Other products/timings and the broader valuable-module queue remain incomplete.
