# Brother supplied-serial qualification, 2026-11-16

This checkpoint adds **one runtime owner, one profile and nineteen functional
cases**, reaching **269 runtime owners in covered paths, 468 profiles and 3,643
historical functional cases**. The [profile](brother_password/README.md) exercises
[the existing module](../../modules/auxiliary/admin/misc/brother_default_admin_auth_bypass_cve_2024_51978.rb)
with a supplied synthetic serial and `ValidatePassword=false`. Earlier coverage
remains historical and the broader campaign remains incomplete. No PR is created.

## Bounded mode and reference

This mode performs local password derivation and genuine Framework credential
reporting. It needs one ordinary-role PostgreSQL container, with a real isolated
host console. There is no printer emulator. Actual HTTP/SNMP/PJL discovery,
accepted/denied device logins, model/firmware compatibility and real factory
password correctness remain unqualified; those paths need a genuine device or
matching runnable firmware.

Nine synthetic vectors come from the
[original research PoC](https://github.com/sfewer-r7/BrotherVulnerabilities/blob/2909a4d3dbbf615321536811bfbbc4a9982b9fb4/CVE-2024-51978.rb),
pinned at `2909a4d3dbbf615321536811bfbbc4a9982b9fb4`. Whole-source SHA256 is
`8fa9f9fa8ed7309ea14b6c5407094e17b1ebc260dc1a6a4e47fd67f68bd98f5f`;
the audited class span is
`f2d99e65ecf75a27191597b9937f09a34cc34df6bb36e6587f6112bf138d525e`.
Only the pure derivation method is called on an allocated reference object,
using Ruby standard libraries. Its constructor, CLI, discovery and login code
are not executed; no dependency is installed. The PoC and module share algorithm
ancestry, so agreement establishes reference consistency, not independent proof
of a real printer password. Normal profile runs use saved vectors and fetch no
external source.

## Confirmed reporting exception and repair

The original module always supplies `DateTime.now` to `create_credential_login`,
even for `Untried`. The credential model requires an unset attempt timestamp
for that status and rejects the update with `ActiveRecord::RecordInvalid`:
`Last attempted at can't be set if status is untried.`

Original run `20261116T201909-5ce3bb` returns from all nineteen public calls.
All fourteen positive calls derive the complete expected value, then raise that
reporting error. Five invalid-configuration cases pass. The ordinary reporting
role and fresh-schema gates pass. Thirteen distinct credentials and default
Untried login rows already exist with null timestamps before the rejected
explicit update. This is a public-run exception, not complete credential loss.

The repair omits the attempt timestamp for Untried status, preserving timestamps
for attempted statuses and all credential/service metadata. Separate-worktree
candidate `ba345f76b2ecf5acfbed3a5e0d8082be6ecb6cab` has identical source bytes to
import `ac211c46bafef796258fb0dcf45b743dcc9ac1d4`. The same eight focused unit
examples have two original failures and zero repaired failures; their reporting
APIs are explicit doubles. Successful, incorrect and unable-to-connect statuses
retain timestamps in those unit cases. No authenticated printer path is claimed.
Parent default invocation passes fifteen examples: eight owner cases and seven
automatically loaded support cases. Strict owner lint is clean before repair;
final owner, unit and functional files have zero offenses. Msftidy passes
before/after. All sixty worker entries and three final-reference entries are
independently rehashed, along with the two imported blobs.

## Harness correction and final acceptance

The first repaired run, `20261116T202615-d8e2a5`, uses the original declared
inputs with only the owning module changed. All nineteen public calls return
without a module exception. One RSpec assertion fails because its first-run IDs
were kept in an instance variable that resets between examples; real database
snapshots already show identical credential/service/login IDs. The harness now
compares the actual before rows with the after rows and explicitly requires a
null Untried timestamp. That failure is preserved separately and adds no cases.

Final run **`20261116T202908-2e0aef`** passes **19 examples, zero failures,
zero pending and zero outside errors**, in 70.15 RSpec seconds. The
[case catalog](brother_password/cases.json) covers short/exact/long serials,
sixteen-character truncation, lookup boundaries, explicit ASCII and eight-byte
UTF-8 salts, HTTP/HTTPS service metadata, all explicit discovery selectors
bypassed by a provided serial, repetition and five invalid settings. Lookup 255
without an explicit salt returns the existing unknown-table-entry reason;
this does not qualify every lookup or salt.

Fourteen positive calls require complete values and actual password credentials
with correct endpoint, TCP service, module origin and Untried login context.
Thirteen distinct credentials and login rows persist across the separate
workspaces; identical repetition preserves core, service and login IDs. All
attempt timestamps are null. The five invalid workspaces persist no credentials.
Every call has empty reserved loopback TCP and UDP queues; those listeners give
no protocol response and no transport/reporting method is stubbed. Jobs and
sessions finish empty, with no loot.

## Inputs, cleanup and review

All **29 consumed paths** match exact tracked blobs in source/fixture commit
`32ed6ad074e69d7f1b9829ef829bbb2104320f83`. Runtime metadata keeps its actual
earlier revision and working-input hashes. The full human guide and Scenarios
remain unchanged: SHA256
`b3da2bc98f9984899de9c73d63debe981a9fc52ad9590d3793716c5ddaba24e9`.
Original/fixed owner hashes are
`83dbce93d1e5f1c9fa9c8afd3f801c5571652c6597f00320edff7766db36846e` /
`b8f0ae32453cab737d61890833232d8cacfbc5e30ca2473abe0572921085676e`.

Each attempt uses one PostgreSQL 16 container at 0.25 CPU / 384 MiB, equal swap,
PID limit 128, init enabled and loopback publication. The final four cgroup
snapshots have zero events. Its attached volume and two networks are independently
absent. All three attempts finish cleanup; global container inventory is empty,
the advisory lock is free and no Brother Ruby process remains. Two unrelated
AWS/GitHub connector containers appearing between attempts are removed under the
user's policy; unrelated images and volumes are not pruned.

The final runtime seal has 76 independently rehashed entries. The qualified
checkpoint seal has **40 entries**, referencing six exact seals with
**297 independently rehashed entries**, including the original and harness-failed
runs, worker evidence, final run and CP Calendar unit-CI evidence. It is stored at
`/Users/dwelch/.codex/reports/brother-password-qualified-checkpoint-20261116`, manifest SHA256
`ecad977c6dd9b4e73877609ddc8636b98db3486df27c7578fc1df1881e14a775`.
Fresh inventory has 5,179 sources, 4,622 candidates, 270 registered candidates,
4,326 pending candidates and 236 pending documented container hints. All 29
source-pinned reviews are current. Registration is not proof of runtime coverage.

**Summary:** The covered public generation/reporting path passes after a narrow
model-contract fix. **What looks good:** Genuine persistence, complete values,
repeat IDs, invalid settings, no device traffic and teardown are verified.
**Concerns:** No material issue remains in this covered branch; shared reference
ancestry and unqualified device paths limit the conclusion. **Suggestions:**
Use a genuine device or matching firmware before expanding authentication claims.
