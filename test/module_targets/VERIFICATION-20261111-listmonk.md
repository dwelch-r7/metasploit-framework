# Listmonk verification — 11 November 2026

The checkpoint is **200 qualified modules, 154 profiles and 1,641 passing
functional examples**. The [Listmonk lab](listmonk/README.md) adds genuine
4.0.0, 5.0.1 and fixed 5.0.2 coverage for
`auxiliary/gather/listmonk_env_disclosure`. A confirmed auxiliary check error
contract is fixed. The broad campaign remains incomplete: 303 documented
container hints still await individual review, alongside unhinted candidates.
Registration of 202 sources is not proof that all those sources pass.

## Targets and independent controls

Each profile runs an unmodified official amd64 Listmonk image, pinned by platform
manifest and config digests in [profiles.json](listmonk/profiles.json). Root
verifies the actual image ID, every vendor filesystem layer, entrypoint and
original image command. The deployed command performs the vendor's ordinary
schema installation/upgrade and starts the real binary as UID 1000. Its actual
process PID/start time and binary/API versions are recorded. PostgreSQL is the
repository's existing pinned 16 image; the actual server reports **16.15** and
passes all native SQL/API controls with each release. No target handler,
authentication response or template function is replaced.

The [vendor advisory](https://github.com/knadh/listmonk/security/advisories/GHSA-jc7g-x28f-3v3h)
identifies 4.0.0 through 5.0.1 as affected and 5.0.2 as fixed. The independent
Python client verifies actual form authentication, invalid credentials,
ordinary preview rendering, both `env` and `expandenv`, and campaign CRUD.
A read-only principal can preview an existing campaign and disclose a fresh
per-run marker on affected versions; fixed 5.0.2 rejects both functions.
That principal's real creation/deletion requests are independently denied.
A restricted campaign manager can create/delete campaigns without user or
settings administration. The fixture uses the actual release's permission
names, including 4.0.0's older campaign permission model.

Native controls run before and after owning calls, making **150 HTTP requests**
in total. Campaign, list, subscriber, template, role and non-secret user content
remain unchanged. Login timestamps/sessions and advancing serial sequences are
expected transient state. The app process identity remains unchanged. Only
preview and campaign CRUD operations are requested; no campaign send is requested.

## Final result

Source revision: `7fb7b6e133a8cdea6e4bf53dad05ec59b48a1f10`.
Run: `20261111T164353-363ed6`. The actual manager and all three observers exit zero.

| Target | Examples | Module calls | Exact loot files | Spec duration |
| --- | ---: | ---: | ---: | ---: |
| 4.0.0 | 8 | 15 | 6 | 70.58 s |
| 5.0.1 | 8 | 15 | 6 | 26.62 s |
| 5.0.2 | 8 | 15 | 0 | 25.37 s |

The **24/0** result has no pending examples or outside errors. Forty-five actual
public module calls cover repeated affected/fixed checks, all six default
variables, fresh markers, HTML characters, Unicode, empty/unset values,
explicit campaign names, restricted management, read-only denial, bad passwords
and native-verified refused target connections. All **12 loot files** match
independently read environment values byte for byte; there are no extra files.
Fixed templates and error paths create no false loot. Named campaigns and
negative paths repeat successfully, and final SQL snapshots confirm cleanup.

Every profile uses three task containers, capped in total at **1,088 MiB and
1.45 CPUs**: app 128 MiB/0.25 CPU, database 192 MiB/0.2 CPU, Framework
768 MiB/1 CPU. Profiles run serially. A 96 MiB PostgreSQL tmpfs creates no Docker
volume. Live inspection verifies actual limits. The first owning console has an
observed prompt and two fresh metadata snapshots with no manually seeded cache;
later profiles use the runner's verified same-invocation cache reuse.

Root verifies all **45 current selected input hashes**, unchanged vendor images,
the same actual Docker engine/context, native state and owning records.
Twenty-four independent cleanup queries verify nine exact containers, three
exact networks, all project-label inventories and the empty global container
list. The bounded cleanup guard also removes unrelated tool containers recreated
by the app; those are not counted as lab target coverage.

The final read-only evidence package contains **383 manifest entries**, SHA256
`d6b6c4ab02187f2fab0bfed30eeace200cde0fd5b484d1ce5b017fda5ed8c6dd`.
Identical contents are hardlinked only inside the sealed package, separately
from the original source and run files.

## Original module failure and fix

Clean original-source run `20261111T163844-07b551` has **8 examples/two failures
on each of the three genuine releases**, with native pre/post controls passing
and identical process/database content. Thirty-three module calls include
twelve exact loot files; all 24 root cleanup queries pass. Its 363-entry seal
has manifest `29a42cd6d7556ddafe57807cbe1cfd53290922e50bdb534c20adbf8fd4381354`.

`check` rescues `Msf::Exploit::Failed`, while the auxiliary login helper raises
`Msf::Auxiliary::Failed`. Invalid passwords and refused connections therefore
abort instead of returning the intended reason-bearing Unknown result. The
source-only fix catches the correct class and distinguishes authentication from
connection/setup failures. It also guards non-object JSON and unusable version
values. Code outside `check`, run/login failure semantics, options and version
bounds remain unchanged. Worker commit `932936755380f363abd5ddd1933a9772e3c10328`
is imported as `60372b625a5` and its worktree is archived after import.

The identical focused suite has **35/15 before and 35/0 after**, including
28 module cases and seven existing formatter cases; root's normal invocation
also passes 35/0. Actual native response captures have provenance/body hashes;
malformed response and boundary cases are explicitly synthetic unit inputs.
The 33-entry source-fix seal has manifest
`8572ba88a1dc91180d90e47fa43238325b0f1673fe82c90df73ef116747e8e7c`.

## Fixture errors and review limits

Initial run `20261111T163339-e1e23b` fails because of newer permission names on
4.0.0, binary-versus-UTF8 string comparison and an unqualified Ruby constant.
These are fixture defects, not additional module bugs; native 5.x pre/post
controls pass. Its 342-entry seal has manifest
`702fae07f3c958ce86515693cf46c68a65c2394cf05d96281b7709a075307d2a`.
A subsequent known-invalid v4 list permission is caught by source review and
the manager is interrupted orderly before owning calls. It exits 130 and removes
all resources; the 212-entry seal is
`2c81494787628b4c0fee9fdef93e26c5734e96246b9b0104dd3b764da5429712`.
The worker's initial mock-shape setup failure is retained separately too.

**Summary:** Genuine target boundaries, native controls, repeated public calls,
exact loot and complete teardown qualify the tested paths.

**What looks good:** Clean original failures and the identical final assertions
separate the module fix from fixture corrections. All source/evidence hashes
verify. Module documentation now states the campaign-management prerequisite;
its human Scenarios remain byte-identical.

**Concerns:** The module still creates a campaign and requires list/template
ID 1. Read-only vulnerability access is a native control, not a supported owning
run path. Missing default IDs and other deployment configurations are untested.
Module msftidy exits two for the same pre-existing duplicate-RPORT and
missing-AutoCheck findings; changed specs/helper have no lint offenses and
documentation checks pass. This report makes no full-CI-success claim.

**Suggestions:** Keep the low-privilege existing-campaign path and missing-ID
handling as later module improvements; continue the remaining module queue.
