# Gopher verification — 11 November 2026

The checkpoint is **202 qualified modules, 159 profiles and 1,718 passing
functional examples**. The [Gopher lab](gopher/README.md) adds genuine menu
collection and database reporting for `auxiliary/scanner/gopher/gopher_gophermap`.
Three confirmed module defects are fixed and replayed. The campaign remains
incomplete: 299 documented container hints still need individual review, alongside
unhinted candidates. Registration of 204 sources is not proof they all pass.

## Genuine target and native controls

The documented `prodhe/gopher` image is pinned by manifest/config digests in
[vendor.json](gopher/vendor.json). Its bundled executable source and Dockerfile
match [vendor commit 971d4ad](https://github.com/prodhe/gopher/tree/971d4ad174ae17943b47d6fbaf2c437eb1d9257d).
Root verifies the actual image ID, every vendor layer, command, unset root-user
configuration and read-only content mounts. No Gopher handler or response is
replaced. A normal bundled BusyBox HTTP daemon supplies an unrelated service;
PostgreSQL **16.15** persists actual Framework records with real authentication.

Native clients read through EOF and record raw menu bytes, independently parsed
rows and target file bytes before and after owning calls. They retrieve a listed
file selector, verify ordinary HTTP file bytes and the real HTTP 400 response to
a Gopher selector, check accepted/rejected database authentication, and prove
port 1 is refused from the owning console's exact network namespace and UID/GID.
There are **18 native Gopher socket requests**, plus HTTP, SQL and refusal
controls. File/source bytes and Gopher, HTTP and PostgreSQL process identities
remain unchanged, with no memory-limit, OOM or PID-limit event.

## Final result

Source revision: `2c4b0c335c8a2450b01488063bb9532ff13bb449`. Run: `20261111T190327-ffa1fd`.
The actual manager and cold-console observer exit zero. All **13 examples pass**,
with no pending examples or outside errors, in **99.87 seconds**
of spec time. The first console has an observed prompt and two fresh metadata
snapshots with no manually seeded cache.

Twenty-five public module calls cover repeated root, nested and spaced-path
menus, information rows, Unicode, explicit locations, empty directory/map,
missing-selector errors, large menus, service identity/deduplication, CSV export,
unrelated HTTP and refused connections. A final-only case rejects the real large
menu twice under a 1 KiB limit with no partial output or service, then reads the
full menu with the default bound in the same workspace.

Root compares every printed row and selector with native order and values. The
full **512-row, 52,739-byte** menu is retained exactly in PostgreSQL. Eleven
positive workspaces contain one correctly named `gopher` service each; HTTP and
refused-port workspaces contain none. Repeated reads do not duplicate records.
Ordinary console CSV export matches native root information after the exporter's
intentional whitespace normalization. Protocol info remains byte-exact in SQL.

The serial project has three containers, capped in total at **960 MiB/1.4 CPUs**:
Gopher 64 MiB/0.2 CPU/64 tasks, PostgreSQL 128 MiB/0.2 CPU/64 tasks, Framework
768 MiB/1 CPU/256 tasks. Live inspection verifies caps, no extra swap, no
privileged container and no Docker volume. PostgreSQL uses 100 MiB bounded tmpfs;
ports bind only to host loopback. Eight independent cleanup queries verify three
exact containers, one exact network, project inventories and an empty global
container list. The bounded guard also removes unrelated tool containers recreated
by the app; those removals are not target coverage.

All **45 current selected input hashes**, native state, actual image identity
and the same Docker engine/context are verified. The final read-only seal has
**199 manifest entries**, SHA256
`a0f6cfe440459571cf05d9e77bc48df1078189b4060119b07b5dded775b87e41`. Identical files are hardlinked only inside the seal,
separately from original source and run files.

## Original failures and fix

Clean original run `20261111T184604-414a64` has **12 examples/four failures** and
19 owning calls. All native pre/post controls pass with unchanged responses,
content and three process identities, zero resource-limit events and all eight
cleanup queries passing. Its 164-entry seal has manifest
`c046840f498feafb8cf84294a4571241f945c59d8b355b476c647463feb3b44f`.

- One `get_once` reads at most one 16,384-byte receive block. A valid 52,739-byte
  menu is incompletely printed and stored as only 16,384 bytes.
- `report_service(service: 'gopher')` uses an unsupported name key. Real SQL
  service names are null and ordinary CSV names are empty.
- An unrelated real HTTP 400 response is persisted as a Gopher service on 8080.

The fix reads complete dot-terminated menus under a total receive deadline and
byte bound, validates all rows before printing/reporting, and uses the correct
`name` field. It follows the stream framing described by
[RFC 1436](https://www.rfc-editor.org/rfc/rfc1436.html). Defaults are ten seconds
and 1 MiB, with positive advanced options documented. Valid empty menus and
optional host/port forms remain supported; unknown types no longer crash.
Expected transport errors disconnect and report concise context without a raw
backtrace. Known-type output and human Scenarios remain preserved.

The identical focused suite has **44 examples/27 failures original → 44/0 fixed**
(37 module and seven existing formatter examples), actual exits 1/0, no pending
or outside errors. Native response origins/hashes are retained; synthetic
fragmentation, malformed, timeout and byte-limit guards are explicitly labelled.
Root independently reruns 44/0 and verifies exact worker source/spec/fixture
hashes. The shared original 12 functional cases now pass; the thirteenth case
adds genuine validation of the new byte limit and recovery.

Syntax, helper/spec lint, docs and whitespace checks pass. Direct canonical
module RuboCop retains two pre-existing findings: percent-literal delimiters and
duplicate RPORT, down from five. Canonical msftidy exits zero while explicitly
skipping this legacy module; this is not treated as a full lint pass. Four old
doc-format findings were repaired outside the unchanged human Scenarios.

## Fixture and audit corrections

A first setup-only run failed because YAML split an unquoted tmpfs value at its
commas. Two created containers never ran; all partial resources were removed.
A second run had no owning calls: rejected PostgreSQL authentication correctly
wrote to stderr while the native assertion checked stdout. A mixed run then had
one extra fixture failure because the helper returned binary-encoded output
instead of its validated UTF-8 copy. These three failures have separate verified
65-, 88- and 161-entry seals. The corrected original baseline passes Unicode.
None is counted as an additional module defect.

The first final root verifier assumed the legacy image's unset User had the same
JSON representation everywhere. Vendor/live configs use an empty string and
modern image inspection omits the value. The comparison now normalizes only
unset User values; command, entrypoint, layer and source checks remain exact.
Both verifier versions and the failed attempt are retained. No functional rerun
or deployment change was needed.

## Scope and review

**Summary:** Genuine menus, reporting, negative paths and bound recovery pass.

**What looks good:** Native bytes, full printed order, real SQL/CSV, repeat runs,
three stable processes, current input hashes and exact teardown agree.

**Concerns:** This vendor implementation normalizes unsupported item types to
error rows. Other implementations/extensions remain unqualified; synthetic unit
guards do not substitute for genuine targets. Existing `druid_js`,
`superset_rce_owner` and `wordpress_admin` profiles still lack current passing
results and remain excluded. Two old module lint findings remain.

**Suggestions:** Keep additional implementation/version work serial and retain
native menu framing/content and reporting controls when changing the parser.

An individual source-hashed ES File Explorer review records a genuine Android
target prerequisite. Its documentation's container hits are `defcontainer`
package names, not deployment instructions. The
[researcher's PoC](https://github.com/fs0c131y/ESFileExplorerOpenPortVuln) requires
an actual app/device state; [Android's emulator guidance](https://developer.android.com/studio/run/emulator-acceleration#restrictions)
restricts nested VM acceleration. This is not a universal container exclusion or
a module failure. No APK/device operation was performed. Inventory now has
18 individual reviews and no stale reviews.

The previous published Selenium head also has a
[Windows command-shell CI failure](https://github.com/dwelch-r7/metasploit-framework/actions/runs/43078683174/job/130725209536):
four examples/one failure after a connection reset during `post/test/file`.
Seven failing-stack/test source paths are identical to the prior published base;
no Selenium module runs in that job. The cause remains unverified, and this is
not reported as green CI. No unrelated code change or job rerun was made.

Reproduce from the Framework root:

```sh
bundle exec ruby tools/dev/run_guarded_module_target_tests.rb gopher
```

Local evidence is under `tmp/module-target-tests/20261111T190327-ffa1fd/` and the
`gopher-verified-20261111` sealed package. Publication is to the user's public
fork branch; no PR is created.
