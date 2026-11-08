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
specs) passing. Integration and campaign rerun are pending.

### Investigation queue

- Redis file upload: pre-existing early returns in `send_file` may leave changed
  configuration on intermediate failures. This is source-observed; reproduce
  before classifying it as a demonstrated target failure.
- Redis extraction: add bounded-result, binary/large-response and ACL cases.
- Apache HTTP: add TLS, Digest/WebDAV and disabled-TRACE configurations.
- Memcached: add large/fragmented values, key limits and non-loopback loot proof.
- PostgreSQL: extend beyond the first version and privileged role; keep session
  and direct-host paths. Review default credential lists to shorten login work.

## Remaining work

- Validate and document the runner and first target family.
- Review existing protocol suites and supply reusable managed containers.
- Review container hints across module documentation and reuse viable labs.
- Expand through reusable network service and web application families.
- Review post modules using suitable real sessions and cover declared types.
- Review other module categories and record justified exclusions individually.
- Investigate failures with target evidence before classifying module defects.
- Repeat meaningful state-changing paths and retain concise evidence summaries.

This is a campaign record, not a claim that the repository-wide goal is complete.
