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
  sentinel value survived. The separate fix worktree is implementing and testing
  failure cleanup followed by another successful upload.
- Redis extraction: add bounded-result, binary/large-response and ACL cases.
- Apache HTTP: add TLS, Digest/WebDAV and disabled-TRACE configurations.
- Memcached: add large/fragmented values, key limits and non-loopback loot proof.
- PostgreSQL: extend beyond the first version and privileged role; keep session
  and direct-host paths. Review default credential lists to shorten login work.
- MySQL/MariaDB: both managed targets passed ten cases with strengthened
  account/hash assertions, retaining each implementation's default authentication.
  MySQL 8 credential hash-format metadata and database persistence remain to be
  qualified; an extraction message alone does not prove downstream cracking.
- Next reusable labs: SSH, SMB, then the existing Tomcat/Axis2 target sources;
  independently validate each setup and expand useful module/session cases.

## Remaining work

- Review existing protocol suites and supply reusable managed containers.
- Review container hints across module documentation and reuse viable labs.
- Expand through reusable network service and web application families.
- Review post modules using suitable real sessions and cover declared types.
- Review other module categories and record justified exclusions individually.
- Investigate failures with target evidence before classifying module defects.
- Repeat meaningful state-changing paths and retain concise evidence summaries.

This is a campaign record, not a claim that the repository-wide goal is complete.
