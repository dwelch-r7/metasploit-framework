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
- Apache HTTP: add TLS, Digest/WebDAV and disabled-TRACE configurations.
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
- Executable generators: separate owner controls found failures in Mac x86
  explicit Mach-O signing and Linux x86 custom ELF templates. These are deferred
  generator issues, separate from the corrected EncodedPayload argument order;
  ordinary native Tomcat command payloads were verified in the fix worktree.
- The isolated Framework console now works with Samba. Extend reverse shell,
  Meterpreter and post-module coverage across declared session types and useful
  delivery families.

## Remaining work

- Review existing protocol suites and supply reusable managed containers.
- Review container hints across module documentation and reuse viable labs.
- Expand through reusable network service and web application families.
- Review post modules using suitable real sessions and cover declared types.
- Review other module categories and record justified exclusions individually.
- Three source-hashed reviews now identify separate Linux-kernel, macOS and Xerox
  device/firmware requirements in `reviews.yml`; these do not establish universal
  infeasibility. Existing Kubernetes fixtures require a host cluster and are not
  a self-contained lab; create an isolated cluster before qualifying those modules.
- Investigate failures with target evidence before classifying module defects.
- Repeat meaningful state-changing paths and retain concise evidence summaries.

This is a campaign record, not a claim that the repository-wide goal is complete.
