# LearnPress field SQL injection, 2026-11-16

This checkpoint adds **one runtime owner, nine profiles and fifteen functional
cases**, reaching **267 runtime owners in covered paths, 459 profiles and 3,607
functional cases**. Earlier coverage remains historical; this is not a whole
campaign replay. The broader goal is incomplete and no PR is created.

The [module](../../modules/auxiliary/scanner/http/wp_learnpress_c_fields_sqli.rb)
maps to these targets through their manifests. The [lab README](learnpress_fields/README.md)
provides preparation and serial guarded-runner commands.

The module has two public actions, CVE-2024-8522 (`c_only_fields`) and
CVE-2024-8529 (`c_fields`), and no public check hook. Real console `run` calls
must return complete native password hashes, persist the correct service-origin
credentials and save exact loot lines. Negative states must reject extraction
and persist nothing. HTTP, SQLi, credential and loot transport are not stubbed.

## Genuine applications and native gates

Official LearnPress 4.2.7 and 4.2.7.1 run unchanged on pinned WordPress 6.8.3 /
PHP 8.3.28 and MariaDB 11.2.2. The release catalog pins full archive and selected
installed-file SHA256 values. Native Core APIs create four genuine users,
activate the plugin and let its own installer create its tables and pages.
A fresh bootstrap then creates a published course through the registered
`lp_course` post type. Inactive and absent states do not fabricate plugin schema.

The native affected/fixed comparison proves the two real module routes,
including independent true/false SQL SLEEP expressions, ordinary login/course
responses, actual roles/source/user/course state and cleanup. Its 54 HTTP
requests and 138 independently rehashed seal entries add no module cases.

Initial probe failures are kept separate. Reusing identical JWT request params
consumed a cached response and invalidated a timing assumption. The frontend
namespace also has a vendor URL gate: a bare query-string route returns a real
404 even while the module's pretty-permalink route is available. One attempted
URL hint did not qualify. These are native-probe/setup assumptions, not module
verdicts. The final controls use different SQL literals for each action/phase.

## Confirmed cached-response defect

LearnPress caches the normalized JWT request parameters before SQL execution.
The original callback's negative two-digit timing nonce has only 100 possible
values. Priming all 100 inputs through real HTTP, followed by three fast cached
rechecks, makes the original public module report `Target is not vulnerable.`
in 0.554 seconds on the affected application. Independent fresh true/false
controls still prove the injection before and after. No randomness is replaced.
An ordinary uncached original run separately extracts one complete real hash.

The callback now selects a strictly negative nonce from one billion through
9,999,999,999, keeping a broad per-request cache key and a safe SQL integer.
The same primed-cache public test then passes in 166.414 seconds, persisting one
native credential and a matching 103-byte loot file. The owner is the only
changed declared input. Original failures, uncached diagnostics and the exact
corrected replay remain separate from final qualification counts.

A separate worktree supplies commit `38a09ec476233021189b9997b1a925a15863cde2`,
imported as `b15c3d56737f4c89d700c380a9788cd6dcbe1bf1`. The same 16 focused unit
cases have ten original failures and zero corrected failures. These model
transport and timing, adding no functional coverage. Strict RuboCop, msftidy,
syntax and diff checks pass before/after; initial unit expectation/style
corrections are retained separately. The worker's 58-entry seal and the
102-entry corrected native replay seal have been independently rehashed.

Original/fixed owner SHA256:
`e4422cd55b261e668c0f0791e90361bd157bbe6ccefdd3a95e7b85d1c6a47dff` /
`da3a15bfad65ca079da9b6b493b062b6492d9c5012a108b2e813d14b2a93f78d`.
The entire human module guide and its Scenarios remain byte-identical:
`0d58bdedf6712de0fe7d041c9f717fb458642b886be889ee3dc26317fd71b175`.

## Retained timing failure

An initial final-fixture run at SqliDelay=0.4 extracted a full-length hash but
persisted two incorrect characters. Native source/users/course snapshots,
cache priming, both-action before/after controls and all twelve OOM/PID rows
pass. Apache captures contain 643 distinct large nonces: no collision is
observed. Bisection reconstruction identifies two native-false comparisons
classified as delayed. The old capture lacks per-request durations, so the
server/host cause remains unverified; a passing bracketing control does not
validate every extraction comparison. The failed run and its analysis are
sealed, and exact credential/hash assertions remain unchanged.

The local fixture delay is raised to 0.6, the call deadline to 540 seconds, and
Apache now records duration_us without altering plugin source or HTTP responses.
Every qualified profile uses those shared module, test and target inputs. The
earlier three profiles/six passes at 0.4 seconds are retained as history and add
no current qualification.
Single-sample wall-clock classification in the shared time-blind helper remains
a timing reliability investigation; this target work does not claim to fix it.

## Bounded test deadlines and retained provenance

The frontend action takes about 1.2 seconds for a true expression at the local
0.6-second SQL delay. Its repeated profile passed both complete extractions in
834.251 seconds, exceeding the previous 600-second RSpec allowance. The runner
now accepts an optional integer `test_timeout` from 1 through 1800 seconds;
omission preserves 600. Only the repeated frontend and both-action subdirectory
profiles declare 1200. Per-console-call, setup, readiness and cleanup deadlines
remain separate. The separate-worktree timeout change has 45 focused guard and
runner examples passing; ten newly added expectations fail on the original,
while the unchanged-default expectation passes on both versions. No Docker or
module coverage is inferred from those unit tests.

Five final profiles were completed before this runner extension: cached, fixed,
inactive, absent and cross-database prefix. Their original input maps and seals
are retained. The executable difference is exactly the reviewed seven-line
optional-deadline extension; all five omit the new option and retain 600. Their
component README also predates a prose-only explanation of frontend timing and
the allowance; every fenced preparation and runner command is identical. All
owner, functional spec, target source, archive pins, resource caps, reporting and
cleanup inputs match the final versions. These are reviewed compatible inputs,
not claims that all historical input bytes match the new commit. The remaining
four profiles use the new runner and exact current declared inputs.

A deliberately interrupted subdirectory run during that maintenance has one
started call and no returned calls. It was terminated and cleaned before any
input changes. Its sealed result adds no cases and is not a module failure.

## Final functional matrix

| Profile | Actual run | Cases | Public calls | Native HTTP | Exact loot | Runner provenance |
| --- | --- | ---: | ---: | ---: | ---: | --- |
| `learnpress_fields` | `20261116T182527-eb3a11` | 2 | 2 | 14 | 2 | Current |
| `learnpress_fields_absent` | `20261116T172426-1ae040` | 2 | 2 | 14 | 0 | Reviewed default-600 predecessor |
| `learnpress_fields_c_fields` | `20261116T175018-fb8e83` | 2 | 2 | 14 | 2 | Current |
| `learnpress_fields_cached` | `20261116T171537-c89c7e` | 1 | 1 | 117 | 1 | Reviewed default-600 predecessor |
| `learnpress_fields_count2` | `20261116T181643-edaa24` | 1 | 1 | 14 | 1 | Current |
| `learnpress_fields_fixed` | `20261116T172137-451167` | 2 | 2 | 14 | 0 | Reviewed default-600 predecessor |
| `learnpress_fields_inactive` | `20261116T172309-d1e84f` | 2 | 2 | 14 | 0 | Reviewed default-600 predecessor |
| `learnpress_fields_prefix` | `20261116T172539-f61286` | 1 | 1 | 14 | 1 | Reviewed default-600 predecessor |
| `learnpress_fields_subdirectory` | `20261116T180446-28da85` | 2 | 2 | 14 | 2 | Current |

All fifteen public runs pass. The final profiles have 229
independent native HTTP requests, 9 exact loot files and
7 deduplicated credential rows. All
108 native OOM/PID event rows are zero. The parent
independently rehashes all 941 sealed runtime
entries and verifies 45
attached volumes/networks absent, along with every selected project and the
global container inventory. The advisory lock is free.

Source/fixtures are committed as `adf414f5a40908ee582f56f422e74f7e5131263a`. The input audit covers
90 unique paths and 92
actual digest variants: 88 current tracked
paths and two ignored catalog-pinned archives. Four profiles use exact current
inputs. Five retain exactly two explicitly reviewed older inputs each: the
runner with its unchanged absent-option default and the nonexecuted README
prose described above. Every owner/spec/target/archive input matches; raw
per-profile input maps and historical seals remain preserved.

The fresh inventory contains 5179 source modules,
4622 candidates, 268 registered
candidates, 4328 pending candidates and
237 pending documented container hints.
Its 29 source-pinned target-requirement reviews are current,
with zero stale reviews. Registration and source-only review add no runtime
qualification.

The matrix covers both actions, repeat execution, a real subdirectory,
custom current-site prefix with a genuine cross-database users backup, COUNT=2,
patched 4.2.7.1, installed/inactive and absent states. Per-profile before/after
native controls verify both routes and ordinary application behavior. Native
snapshots cover selected source, users, course and configuration state; they are
not complete database dumps. Reporting uses an ordinary PostgreSQL role and a
fresh schema. A failed native gate is not proof of correct module rejection.

## Reproducibility, resources and limits

Each serial stack has at most three capped containers: app 1 CPU / 512 MiB,
MariaDB 0.5 CPU / 512 MiB and reporting PostgreSQL 0.25 CPU / 384 MiB. Swap equals
memory, PID limits are 128, init is enabled and published ports bind loopback.
The reporting service reuses an existing component without starting its app.
Each stack must be removed before the next; final evidence must independently
verify projects and attached volumes/networks absent and the advisory lock free.
Personal orchestration removes unrelated containers under the user's explicit
instruction. A transient unrelated fourth container during the corrected
cache diagnostic was removed; the work stack itself stayed within three.

The lab README supplies preparation and the serial guarded-runner commands.
SqliDelay=0.6 is exercised locally with independent native controls. Complete bcrypt hashes
still take minutes; this delay does not qualify noisy remote networks. Other
WordPress/PHP/database releases and SQL modes, TLS/IPv6, plain permalinks,
empty-course catalogues and COUNT=0/all-row extraction remain unqualified.
Earlier campaign coverage remains historical. The broader goal is incomplete,
and no PR is created.

## Review

Summary: Nine genuine profiles pass all fifteen cases; every selected stack is
removed and the wider campaign remains active.
What looks good: Native cache A/B changes only the owning module; complete
credentials/loot and genuine fixed/missing-prerequisite applications arbitrate
functional results. Human Scenarios are preserved.
Concerns: The retained 0.4-second character corruption has no established
server/host root cause; noisy-network timing remains unqualified. Five profiles
retain the explicitly reviewed runner/documentation predecessors.
Suggestions: Keep those timing and provenance limits visible, follow actual
publication checkouts, and continue genuine-target qualification from the
remaining inventory.
