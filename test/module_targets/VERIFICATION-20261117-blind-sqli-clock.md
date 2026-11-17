# Blind SQLi monotonic timing and replay, 2026-11-17

This checkpoint qualifies the remaining WordPress core SQLi subdirectory profile:
**zero new owners, one profile and two cases**, reaching **272 runtime owners in
covered paths, 497 qualified profiles and 3,702 historical functional cases**.
The [earlier ten-profile attempt](VERIFICATION-20261117-wordpress-core.md) remains
exit 1 with its real corrupted hash preserved. Nine profiles were accepted there;
this separate two-case replay exits 0. No all-green 24-case aggregate is claimed.
The broader campaign remains incomplete. No PR is created.

## Independently confirmed clock defect

Shared `TimeBasedBlindMixin#blind_request` measured query callbacks with two
`Time.now` reads. Independent deterministic clock inputs prove that a forward
wall-clock step can turn a fast callback into a false positive and a backward
step can conceal a real delay. These are simulated unit clocks; the host clock
is never changed. They do not establish that a clock step occurred during the
earlier subdirectory corruption.

The repair uses the existing `Rex::Stopwatch.elapsed_time` helper, whose installed
implementation uses `Process::CLOCK_MONOTONIC`. It explicitly requires that helper
for library-only loading. The inclusive `>= SqliDelay` boundary, callback input
and count, Boolean return shape and original exception identity are preserved.
Candidate `659362cee6a58907eaf3aaf9b40238ccfb4a65ff` is imported as
`ff34fbac32e0209483d4d7271dfc342b5af94468`.

Eleven new unit cases cover fast, slow, exact/below boundary and zero durations,
truthy/nil/false callback results, callback invocation, exception identity and
both clock directions. Existing ordinary SQLi timing fixtures deliberately
advance simulated wall and monotonic clocks together; no sleeps are introduced.
The identical 105-example SQLi folder and seed 41927 has exactly two original
failures, both new clock-step regressions, then zero fixed failures. An initial
candidate missing the explicit stopwatch require produces NameErrors in a cold
library load; that failed evidence is retained and the final require fixes it.

Parent integration passes **120 examples, zero failures, pending cases or outside
errors**, combining the SQLi folder and existing owner alias suite. All five
changed Ruby files are lint-clean with exact candidate blobs independently
verified. The actual installed rex-core 0.1.37 stopwatch source is byte-checked.
These units use explicit callback/clock doubles; they are not genuine SQL cases.
BENCHMARK calibration has a separate wall-clock measurement and remains outside
this narrow request-classification repair. Other database backends are not
claimed as genuine runtime tests.

## Genuine public subdirectory replay

Run `20261117T023852-06ef9a/wp2shell_subdirectory` executes public `check` and
`run` against a fresh real `/wordpress` installation on official WordPress 6.9.4,
PHP 8.3.28 and MariaDB 11.2.2. Both pass. The complete 63-byte native hash matches
its credential and exact loot file; service, endpoint, type and module origin
are correct. Check and run workspaces each retain their proper finding. No
HTTP, SQL, protocol or reporting method is replaced. Both native control phases
pass, source/users/posts/metadata/configuration remain equal, and jobs/sessions
finish empty. The 22 native gate requests are not extra functional cases.

All **71 declared input paths** match source commit
`ff34fbac32e0209483d4d7271dfc342b5af94468`: 67 tracked blobs and four ignored
official tarballs. The failed and passing profiles have the same declared input
set; only `lib/msf/core/exploit/sqli/time_based_blind_mixin.rb` differs. The owner,
functional spec, fixtures and human guide are unchanged. The old library SHA256
is `37eeb84ebbc05484f944a44922f256e1cd64ad024ae2d7aabdbba8a649222950`;
the new one is `585a46a1ab427e714e50a6847626f3f0dc7c2f30c12a592930fa71aaa434a3fd`.

The historical byte corruption's cause remains **unverified**. A failing genuine
sample, an independently proved library defect and a passing fixed-source sample
do not prove that historical wall-clock movement caused that failure. Both raw
captures and the earlier server-timestamp reconstruction remain available for
further investigation. The other nine profiles retain their earlier qualified
source revision; they are not silently relabelled as new-library executions.

One stack runs at a time, with the existing three-container CPU/memory/PID/swap
caps and loopback ports. Work/global maxima are three. All twelve OOM/PID
snapshots have zero events, all five attached volumes/networks are independently
absent, global containers are empty and the guarded command exits naturally 0.
No unrelated containers appear in this replay and no unrelated images or volumes
are pruned. The human SQLi/RCE guides and Scenarios remain unchanged.

The new passing runtime has 101 independently rehashed entries. The checkpoint
seal preserves both raw outcomes, the unit comparison and parent verification:
`/Users/dwelch/.codex/reports/blind-sqli-clock-qualified-checkpoint-20261117`,
manifest SHA256 `ea83f294c28b08925e6d9dcb68fc91399df835a85b0e196ce87ab49ee5e0ee68`;
20 entries reference 4 exact seals / 305 independently rehashed entries.

The separate RCE owner's native prerequisite probes are preparation only and add
no module/session coverage to this checkpoint. Public typed-session testing is
still separate. Publication CI remains tracked against its actual source commit.
