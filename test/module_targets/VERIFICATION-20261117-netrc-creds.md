# .netrc collection and parser repair, 2026-11-17

Qualified [post/multi/gather/netrc_creds](../../modules/post/multi/gather/netrc_creds.rb)
with **eight passing functional cases in one aggregate with exit 0**, reaching
**285 runtime owners in covered paths, 579 qualified profiles and 4,020
historical functional cases**. The broader campaign remains active. No PR is
created. The existing rsync profile also passes its five-case shared-helper
regression; those cases are not added again.

## Reproduction and independent prerequisites

Use the command in the [target guide](netrc_creds/README.md). The profile reuses
the existing digest-pinned Ubuntu 22.04 client, Apache 2.4.62 Basic-authentication
fixture and PostgreSQL 16 reporting service. Curl is pinned and observed as
`7.81.0-1ubuntu1.30`, with Python `3.10.6-1~22.04.1`. Actual image IDs report
Linux/amd64. Native controls download the exact protected response with correct
credentials and receive 401 with wrong or absent credentials.

The [upstream curl 7.81 parser](https://github.com/curl/curl/blob/curl-7_81_0/lib/netrc.c)
uses whitespace token boundaries and skips comment lines. Its source is a lead,
not the runtime oracle: two standalone native cohorts, including an exact-package
repeat, each pass 18 real HTTP controls. They accept multiline, inline, tabbed,
commented and multiple-machine files, including both actual server aliases.
An apparent machine inside a comment receives 401 when routed to the same real
Apache service. No authentication response or parser is simulated.

Each owning case installs an exact target-only home file with mode 0600, checks
its ownership/permissions and executes native curl against that actual path as
the selected user. Framework then generates and executes genuine ELF shell
payloads. Native callbacks establish the Docker-to-host route; actual session
events/database records and target-side marker UID establish each shell. The
same active owner's session file API must read the native file's exact SHA256,
or return the expected unreadable result. The owner declares only shell sessions.
Payload execution is a prerequisite, not a netrc exploit claim.

An ordinary PostgreSQL role starts with an empty schema and Framework creates
its real reporting schema. Direct queries inspect actual loot records, and the
saved host files are parsed as CSV and matched to their exact metadata/content.
The original owner stores CSV loot rather than credential cores. Loot does not
itself establish that a password authenticates.

## Confirmed failures and owner-only comparison

Original run `20261117T220325-949ecf` has **4 examples/2 failures**, with zero
pending/outside errors, five owning calls, four real shells and successful
teardown. Multiline collection and its repeat produce correct CSV; the
ordinary-user unreadable-file negative passes. Two actual parser defects remain:

- Literal single-space patterns miss the native-working tab-separated file,
  producing no loot despite correct session file bytes and native HTTP 200.
- A full comment line is parsed as an extra `bogus,bogus,comment.invalid`
  credential alongside the real account. Native authentication from that
  comment-only machine is rejected.

All 22 native HTTP controls, before/after file/fixture maps, session/process
cleanup and all four home-file recoveries pass. No harness correction was needed
to establish this original cohort. Its failures are retained separately from
successful setup and cleanup.

The repair accepts whitespace in the existing token patterns, skips full comment
lines and guards nil file reads. Original owner SHA256 is
`f567e254e4a74ca9146a6d9a4730a10891fb1ca688c1d7cc9c4ad54f44f0ba3b`;
repaired SHA256 is
`d40f68fa1605d4d57972e0c12d862ca6ce9d6313b62cb09925093c84871a3e6d`.

Run `20261117T221134-31c68b` passes the unchanged netrc cohort **4/0**, with
the same five calls/four sessions. Of 58 declared inputs, only the owner changes;
the other 57, including the fixture, spec and helpers, are byte-identical. Tabs
now yield the correct CSV and comments yield only the actual account. The same
serial CLI then passes **5/0 rsync cases**, with its helper the sole changed
input from the earlier rsync checkpoint. Owner/resource/observation hooks preserve
the original rsync defaults while sharing its real callback, shell and recovery
controls. The complete nine-case CLI exits 0 and both stacks are removed.

The separate focused contracts retain six native files and the original real
multiline CSV. The identical final spec has **13 examples/3 failures** on the
original, then **13/0** on the repair and **13/0** again. Two failures match the
native tab/comment defects. The third is an explicitly synthetic nil-read
continuation boundary; a file-disappearance race was not reproduced natively.
Transport, Framework/session access, persistence and output are doubled there;
the real owner, Rex table and CSV generation run. These unit examples do not
qualify genuine sessions or database persistence.

## Selected final aggregate

Run `20261117T221905-efcbe8` passes **8/0**, with no pending/outside errors and
successful teardown. Its cases take 220.2 RSpec seconds, including prerequisites
and recovery:

| Case | User | Calls | New CSV loot files |
| --- | --- | ---: | ---: |
| Multiline and same-instance repeat | root | 2 | 2 |
| Tab-separated fields | root | 1 | 1 |
| Commented example excluded | root | 1 | 1 |
| Root file unreadable to ordinary user | labuser | 1 | 0 |
| Inline fields | root | 1 | 1 |
| Both machine aliases | root | 1 | 1 |
| Multiple ASCII spaces | root | 1 | 1 |
| Ordinary user's own home file | labuser | 1 | 1 |

Nine actual module calls use eight typed Linux shells: six root and two ordinary
users. Eight unique loot records/files contain nine expected CSV data rows,
including both machine aliases. All queried credential-core counts remain zero.
Repeating on the same module object creates a new loot record/file with identical
CSV bytes. The multiple-space fixture derives from captured tab bytes and passes
its own real client gate before collection is tested.

The selected aggregate has **26 native HTTP controls**: 19 exact-body
authenticated successes and seven authentication denials. Console completion
alone is never a collection verdict. Stored file paths stay inside the isolated
Framework configuration's loot directory. Collected loot remains intentional
test evidence; no Successful login status is asserted.

## Recovery, resources and limits

Native operator recovery deletes each of the eight installed home files only
after matching its fixture bytes. All eight remote processes terminate,
Framework registrations disappear and database session records close. Only
hash-checked generated ELFs and exact session markers are removed. Final sessions
and jobs are empty. Selected passwd/group and home-file maps and all fixture
hashes/metadata match before and after. This is selected-state recovery, not a
claim that logs, counters or the complete filesystem are unchanged.

One capped stack runs at a time: at most **three work containers**, totaling
1 CPU/768 MiB, with equal memory/swap, PID128 and init. Resolved configuration
and actual container limits are checked; ports bind only to loopback. Twelve
cgroup snapshots have zero OOM/PID-limit events. The database volume and both
networks are individually absent after teardown; no containers remain. Unrelated
images and volumes are not pruned.

Changed Ruby syntax/RuboCop, owner msftidy, Python/shell syntax and both Compose
plans pass. The separate RuboCop invocation covers the legacy owner despite
msftidy's automatic skip notice. No full RSpec suite runs. Immutable private
archives preserve original failures, native and unit captures, the owner-only
comparison, shared-helper regression and all 59 final declared inputs. Native,
unit, preliminary replay and rsync regression cases are not counted again in
the eight newly qualified cases. Publication CI is separate from these opt-in
target tests. No human Scenarios are created or modified.

Other platforms/architectures, consumers or curl releases, quoted credentials,
macros/default-machine entries, inline comments, token ordering/case variants,
additional credential formats and transport loss remain unqualified. The owner
has no check method or action variants.
