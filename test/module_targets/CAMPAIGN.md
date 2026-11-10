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

## Remaining work

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
