# Native SuiteCRM usernames and roles, 2026-11-18

The three genuine SuiteCRM profiles pass **22/0**, zero pending/outside errors.
Six new cases add one profile for an existing owner; sixteen regression cases
are not counted twice. Totals reach **301 runtime owners in covered paths,
614 qualified profiles and 4,305 historical functional cases**. The broader
goal remains active; no PR is created. The [shared guide](suitecrm/README.md)
and [names guide](suitecrm_names/README.md) provide the guarded commands.

## Genuine prerequisites and original failure

Official 7.12.5 and fixed 7.12.6 use pinned PHP 7.4.33/MariaDB 10.6.19 and unchanged
export handlers. The stock installer and User/Account APIs create actual users
and records. The native nonadministrator username `aé,o'neil` stores exact raw
bytes and successfully logs in, exports the Account and reproduces the Boolean
injection. Early stdin bootstrap and raw bean-input mistakes are fixture
failures, corrected through a normal CLI file and stock to_html/from_html
contract. Neither produced a Framework verdict. The
[earlier verification](VERIFICATION-20261118-suitecrm.md) records release/setup
provenance, original passive-check/COUNT repairs and the unresolved CVE mapping.

A genuine Framework helper baseline authenticates and infers usernames through
native HTTP, then stops before hash extraction. One valid selected username
becomes two: `a\xC3` and `o'neil\x00`, rather than the exact UTF-8 value.
It fails **1/1**, with zero outside errors, unchanged native before/after state
and successful cleanup. This is a helper-inference baseline, not a completed
primary-run verdict. Focused initial synthetic tests reproduce 23/12 failures.

## Repair, rejected candidate and wire correction

Individual HEX rows preserve boundaries and UTF-8 without GROUP_CONCAT limits.
COUNT defaults/order/NULL-ignore behavior remain; exact binary literals select
hashes. Finite binary byte extraction replaces character SUBSTR indexing; the
shared expanding length detector removes the old 800-byte ceiling.

The first direct-oracle candidate passes 62/0 focused cases but fails real wire
validation: SuiteCRM encodes `>` as `&gt;`, producing SQL1064. Error-page length
was misread as true and doubling did not converge. The exact guarded runner was
interrupted; cleanup passed and all task processes stopped. That candidate is
sealed and unqualified. Its missing summary after interruption was a wrapper
assumption, subsequently corrected; it is not a module failure.

The correction adapts generated length comparisons to NOT BETWEEN and uses that
grammar for byte inference. Non-CSV responses abort before entering the oracle.
Focused tests use the actual HTTP form builder plus an explicitly synthetic
model of observed target escaping: 33 cases/6 failures before, **70/0** combined
after. Syntax, module tidy and changed Ruby lint pass with zero offenses. The
module-document checker retains ten baseline warnings with zero new warnings.
The static inventory has 5,179 sources, 4,293 pending selectable candidates, 222
pending documented container hints and zero stale reviews.

## Final native replay

Run `20261118T200453-4ed8b0` passes names 6/0, baseline 8/0 and fixed 8/0 with
**56 unchanged declared inputs**, 28 check/run requests and
176 source trace events. Independent native HTTP captures total 94.
Native ordinary/Boolean exports, exact CSV headers, safe comparison contrasts,
correct/wrong login, original handler hashes and selected database state pass
before and after. Native SQL separately confirms the 1600 length and raw username
HEX; actual Framework SQLi returns both 1600 and exact UTF-8 column bytes.

Administrator COUNT=1 to COUNT=0 and repeated nonadministrator COUNT=1 cover both
AutoCheck modes. Selected names and all persisted bcrypt/type/JtR/origin/endpoint
rows match native data exactly, with no duplicate rows on repeats. Bad passwords
refuse collection; reason-bearing passive/fixed/unknown checks retain coverage.
The original baseline/fixed eight-case profiles both pass. Sessions/jobs remain
empty and selected native user/Account state is preserved.

All 36 memory/PID event captures are zero. All **50 created Docker objects** from
this cohort's probes and functional attempts are independently absent. Three
capped services run serially; completed stacks are removed immediately. Unused
task-created containers up over an hour are removed; unrelated ones are preserved.
Only root path, these releases/runtimes and the recorded local roles/names are
qualified. Other names, versions, engines, URL prefixes, TLS and further ACL/
authentication configurations need separate native evidence. Human Scenarios
are unchanged. Local results do not establish fork CI checkout/execution.

## Sealed local evidence

- Final: `suitecrm-edge-functional-20261118T200452`, 167 files;
  `b76d0bf1f6d03620f685511e5696b5512791df5103b1d0141b56166237e040f9`.
- Original helper baseline: 83 files;
  `3b239d0be21068bd74ba4dbc6ed728c023432baf2b3dcfa40184a1d6863763d5`.
- Rejected native candidate: 93 files;
  `7dab8ad8c10bb22f5c3f70e13db2e5f50f413bc4ffd75ba3407bb46dffdfd995`.
- Native account gate: 76 files;
  `72876e3dcaa07054998c5aed541e82083286c8402d7e8fdaaafbb1af104b2904`.
- Initial source repair: 114 files;
  `6f3eb7a846c493ac3e44ea35bdbd5852d06e37f3a61137e6ab54cb171688efee`.
- Wire correction: 46 files;
  `7b0feac9756bd05e50b653b01c457902beeb9c37df77c91e585c3ea7d3388279`.

Capsules retain inputs, real HTTP/database bytes, source traces, reporting and
cleanup evidence outside Git. Compose, fixture sources, specs and guides live
in Framework. No full local suite was run.
