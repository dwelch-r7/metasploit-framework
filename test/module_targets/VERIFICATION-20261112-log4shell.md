# Log4Shell scanner verification — 2026-11-12

## Summary

`auxiliary/scanner/http/log4shell_scanner` is qualified for the generic actual-library
HTTP scope below: **24 examples, 48 public module runs, zero failures, pending
cases or outside-example errors**. The campaign reaches **214 qualified modules,
203 profiles and 2,104 functional examples**. Registration covers 216 source
modules; 288 documented container hints remain pending and no review is stale.

The production scanner and its documentation are unchanged. The tested commit is
`96d09470a2f72e6f73263d25e176797074710d92`; the owner SHA-256 remains
`0c99025a240dc811b182feb7d9c9d3253b1e32fb38ca51be4415745de5402484`.

| Profile | Examples / failures | RSpec duration |
|---|---|---|
| log4shell_2141 | 6 / 0 | 98.041 s |
| log4shell_2171 | 6 / 0 | 52.181 s |
| log4shell_disabled | 6 / 0 | 52.690 s |
| log4shell_jul | 6 / 0 | 55.289 s |

All four profiles ran serially in `20261112T142713-d06788`. Each retains 44 exact
current input fingerprints, 50 distinct across the matrix. The manager and the
independent observer both exited zero. The first console prompt, BOOT and two
fresh metadata snapshots were observed while live; only later profiles in the
same invocation used its verified metadata seed.

## What looks good

The source-built target calls genuine Apache Log4j API/core libraries; it does
not manufacture vulnerable HTTP responses. Its pinned JDK reports Temurin
1.8.0_412. Build-pinned vendor JAR hashes, loaded code sources, implementation
versions and actual runtime identity agree with the native oracle. Published
Maven checksums were checked during artifact selection; SHA-256 and size are
verified on every image build. Sources and build instructions are included;
no downloaded JAR or opaque binary is added to the repository.

Before Framework scans, independent Python controls send real logged input to
headers, an obfuscated decoded path and a query, plus an unlogged control. A
loopback LDAP collector records genuine BER bind/search traffic from Java's JNDI
client and returns only successful empty results. Python independently decodes
the captured searches/responses and compares expanded OS, Java, environment and
property values. Log4j 2.14.1 performs lookups; 2.17.1, disabled message lookups
and the standard Java logger do not. Remote URL class loading stays disabled.

Each functional case runs twice. Short header/URI files cover blank/comment
lines, one/two logged headers, GET/POST, both obfuscated path variants, query
insertion, optional caret-separated sentinel leaks and an unlogged endpoint.
Real HTTP requests and method counts are asserted against the target journal.
Fourteen callback success messages occur only on the vulnerable logged inputs.
PostgreSQL checks verify the actual target address, port, vulnerability name,
OS/Java details, optional expanded values and both CVE references. Repeat scans
respect existing vulnerability-record deduplication. Every run proves no LDAP
listener remains and no job/session is active.

Each profile uses **three containers**, capped at **960 MiB, 1.5 CPUs and 416
tasks** in aggregate: target 192 MiB, Framework 640 MiB and PostgreSQL 128 MiB.
Memory/swap limits match. Native and functional cgroup checks show no OOM kills
or PID-limit events. All 32 current functional parent cleanup queries pass;
30 more verify the five native calibration environments, including the first
failed test assumption. All 32 parent queries for the retained first functional
matrix also pass. Docker is empty after teardown.

Strict RuboCop passes both new Ruby files. The tagged acceptance dry run selects
exactly six examples per profile. No full RSpec suite was run. The module guide,
including its human Scenarios, remains byte-exact.

## Concerns

Two test-fixture assumptions were corrected using actual captures. The first
native assertion incorrectly required one LDAP lookup per message; the genuine
library repeats unresolved substitutions after an empty LDAP result. The final
oracle requires callbacks exactly when appropriate and validates every captured
search's fully expanded DN and empty response, without inventing a fixed count.

The first functional run, `20261112T142114-4126cb`, had five positive-case
failures because SQL `inet::text` includes `/32` while the test expected a plain
address. All three negative profiles passed. The helper now uses SQL
`host(address)`, preserving correct host, port and reporting checks. The full
matrix was rerun from a fresh console. These were fixture errors, not verified
module defects. Failed evidence and its exact inputs remain separately sealed.

This qualifies generic scanner behavior against the actual vendor library, not
Struts/Solr/vCenter logging configurations, exploit delivery, sessions, every
Log4j/JDK version, arbitrary metadata characters or IPv6. The existing Druid,
Superset RCE-owner and WordPress-admin exclusions remain unchanged. No PR was
created. CI is recorded separately at the published commit; local results do
not imply a CI verdict.

## Suggestions

Continue with `exploit/multi/http/log4shell_header_injection` in a separate target
profile: native harmless remote-class/gadget proof must establish the required
trust and dependency configuration before Framework exploitation. Preserve these
scanner inputs. Verify explicit-header and discovery paths, repeat actual
sessions/commands and all listener cleanup. Windows needs a genuine separate
Windows target. This source review is not an exploit runtime verdict.

Reproduce the scanner matrix with the command in
[the target documentation](log4shell_http/README.md). The original module's
human target examples remain in its existing guide.

Private read-only evidence: `/Users/dwelch/.codex/reports/log4shell-verified-20261112` has 342 manifest entries,
50 distinct input files and SHA-256
`e59f873067d24c590611b599c5a7dec610d359a1dc9898ca745cb3ab176784bb`. Every sealed file's hash, mode and independent inode
were verified. The first functional failure seal has 332 entries
and manifest SHA-256 `b3121928cbe3619b092594f5f103793830a2fa545e18159d109e4637f80f2246`. These machine-local captures
contain transient addresses and remain outside the public repository.
