# 4gaBoards verification — 12 November 2026

The checkpoint is **206 qualified modules, 176 profiles and 1,914 passing
functional examples**. The [new lab](4gaboards/README.md) adds four serial
profiles for `auxiliary/gather/4gaboards_users_info_disclosure_cve_2026_53959`.
The campaign remains incomplete: 295 documented container hints and unhinted
candidates still need review. Registration of 208 sources is not qualification.

## Genuine targets and results

Official 3.3.8 and 3.3.9 amd64 images are pinned by manifest/config digest in
[profiles.json](4gaboards/profiles.json). Their normal Node startup initializes
the real 29-table PostgreSQL application schema. Native reads verify relevant
controller source against the official tags. No HTTP handler or module method
is replaced. Native API and actual application SQL establish that registration
creates a non-administrator account.

The [fixed upstream controller](https://github.com/RARgames/4gaBoards/blob/v3.3.9/server/api/controllers/users/index.js)
uses the [sanitizer](https://github.com/RARgames/4gaBoards/blob/v3.3.9/server/api/helpers/users/sanitize.js)
to retain only `id`, `name`, `username`, `avatarUrl` and `deletedAt` for other
users. A reader still sees its own full profile. On 3.3.8 the same ordinary
reader also sees the administrator's fixture email, phone, organization and SSO
email. The fixture uses real database rows and target API authorization.

Final source: `3ac543383ab9a9a0201b185af20e74fa70fa9d62`.
Run: `20261112T004024-fe8f36`. The manager and all four live observers exit zero.
No examples are pending and no errors occur outside examples.

| Target | Examples | Failures | Spec seconds |
| --- | ---: | ---: | ---: |
| 4gaBoards 3.3.8 | 11 | 0 | 178.86 |
| 4gaBoards 3.3.9 | 11 | 0 | 150.53 |
| 3.3.8 with registration disabled | 3 | 0 | 50.35 |
| Apache 2.4.62 control | 3 | 0 | 37.76 |

The first console has an observed prompt, BOOT record and two fresh metadata
snapshots without a seeded cache. Later consoles use only the observed normal
seed from that invocation.

Independent native checks establish ordinary pages, accepted/rejected database
and administrator credentials, missing/invalid-token rejection, registration,
duplicate-email rejection and affected/fixed user-list behavior. A refused port
is proved through the actual console's socket API. Before/after checks preserve
controller files, process identity, core configuration, protected profile fields
and active fixture identities. The Node application's memory/PID events stay
clean. Reporting uses a separate database from the application.

All **38 public module calls** cover repeats, administrator username/email,
missing/partial administrator options, bad credentials, mixed-case and invalid
email, existing email, missing paths and refused ports. All **16 complete JSON
loot files** equal the independently captured native profiles, with the public
projection applied for fixed targets. Real SQL verifies **14 HTTP services and
7 CVE records**, all seven on the affected release. The patched release retains
public loot and service reporting without false vulnerability records.

Administrator cases verify that the module soft-deletes its created account and
records the administrator's identifier. Missing/partial/bad credentials leave
the account active as reported; native API cleanup removes it after that state
is asserted. Historical soft-deleted user/action rows persist until project
teardown. The test does not credit native cleanup to the module.

## Reproduction, fix and review

Original run `20261112T002047-a98c4f` executes 28 examples with eight failures:
two admin-email cases fail before module invocation because a new test passes
a datastore hash as Ruby keyword arguments. The other six failures reproduce
false CVE records on genuine fixed 3.3.9 responses containing only public fields.
All native before/after controls and 32 cleanup queries pass. Both failed-case
classes remain separately classified in the immutable original evidence.

The source fix evaluates recognized private values after excluding the newly
registered account. It preserves public JSON collection, HTTP service reporting
and administrator cleanup. A false administrator flag is meaningful disclosed
private data; null/empty fields and unknown public fields do not prove this CVE.
The parent separately corrects the test-call braces and adds explicit native/SQL
non-administrator assertions before the final full replay.

The independent paired unit comparison uses the same **16 module examples**,
spec SHA256, order and seed 49103. Original source exits 1 with seven failures;
the fix exits 0 with none. Two complete, unmodified native GET responses have
recorded provenance. The real module loader, options, JSON parser, URI builder
and cleanup flow run in process; HTTP delivery, generated password, reporting
and loot boundaries are disclosed doubles. These units do not prove target
authentication, SQL persistence or Docker behavior. Functional tests supply
those separate controls.

Changed Ruby RuboCop, module msftidy, Python syntax, module documentation and
whitespace checks pass. Human-written Scenarios remain byte-identical.

**Summary:** Affected/fixed collection, reporting, cleanup and refusal paths pass.

**What looks good:** Native privilege and response evidence agree with complete
loot, real records, repeat behavior and exact teardown. The fix is confined to
the vulnerability reporting decision.

**Concerns:** Other versions, TLS/subpath deployments, demo mode and registration
that grants administrator rights remain unqualified. Mail and SSO values are
disclosure fixtures; no external provider authentication is tested. Existing
`druid_js`, `superset_rce_owner` and `wordpress_admin` profiles remain excluded.
Inventory has 18 individual reviews and zero stale reviews. CI is assessed
separately from local acceptance.

**Suggestions:** Continue the remaining feasible modules with the same serial
resource budget and distinguish fixture failures from module defects.

## Resources and evidence

Application profiles use three containers capped at **1,344 MiB/1.55 CPUs**:
target 384 MiB/0.35 CPU/64 tasks, PostgreSQL 192 MiB/0.2 CPU/64 tasks and Framework
768 MiB/1 CPU/256 tasks. Apache control totals 960 MiB/1.3 CPUs. Live inspection
verifies caps, equal memory/swap limits and loopback-only published HTTP.
Database/upload storage uses bounded tmpfs; no anonymous or named data volumes,
privileged containers or Docker socket mounts are present.

All **56 selected input hashes** are current. The **32 independent cleanup
queries** verify exact containers/networks, project inventories and an empty
global container list on the same engine/context. Each project is removed
before the next runs. The earlier two-container native pilot has seven further
passing cleanup queries. An initial pilot configuration error creates no
resources and supplies no module verdict.

The final read-only package `4gaboards-verified-20261112` has **405 entries**;
manifest SHA256:
`a370e510fc6713829a8b76ea188f4d58bca8c2bb8abdc23392ae40be2eb43055`.
Original evidence is a separate 352-entry package, manifest
`4922a830691c58e03531af5c13f18f3c70aaf51fa68c8ad717a5ee3225d4f050`.
The source worker's independent 25-entry unit package is copied and reverified
in the final evidence. Raw runs remain under `tmp/module-target-tests/`.
Files are independent of active source/run files and rehashed before publication.

```sh
bundle exec ruby tools/dev/run_guarded_module_target_tests.rb 4gaboards_3_3_8 4gaboards_3_3_9 4gaboards_registration_disabled 4gaboards_unrelated
```

Publication is to the user's fork branch; no PR is created.
