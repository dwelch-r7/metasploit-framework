# Selenium verification — 11 November 2026

The checkpoint is **201 qualified modules, 158 profiles and 1,705 passing
functional examples**. The [Selenium lab](selenium_file/README.md) adds four
genuine vendor browser/Grid profiles for `auxiliary/gather/selenium_file_read`.
Confirmed false-success and browser-session cleanup defects are fixed and
replayed. The campaign remains incomplete: 301 documented container hints await
individual review, alongside unhinted candidates. Registration of 203 sources
does not establish that all those sources pass.

## Targets and independent controls

The unmodified official amd64 images are pinned by platform manifest and config
digests in [profiles.json](selenium_file/profiles.json). Root verifies the actual
image IDs, every vendor filesystem layer, entrypoint, command and UID 1200.
Read-only data fixtures and a normal loopback Python HTTP server are the only
mounts. No browser, driver, Grid API handler or response is replaced. Vendor
deployment sources are pinned at
[3.141.59](https://github.com/SeleniumHQ/docker-selenium/tree/163cc7d75ad5f24694dc233db10b9dd1ea13aae4)
and [4.27.0](https://github.com/SeleniumHQ/docker-selenium/tree/f353914db44470765311f2a42f302bf935e7428d).

Native clients independently create/read/delete browsers before and after the
owning module calls. They compare actual target bytes and browser-rendered text,
record actual browser/Java/process identity, verify missing and unreadable files,
and check HTTP/redirect behavior. Refused target port 1 is independently proven
from the owning Framework network namespace and UID. Native controls make
**526 WebDriver API requests**, including per-call
session audits. Target file bytes and process identities remain unchanged, with
no PID-limit or OOM event.

## Final result

Source revision: `7e49d052bd858104a3926358d55a5142b5ad76a2`. Run: `20261111T181635-34813d`.
The actual manager and all four observers exit zero.

| Profile | Actual browser | Examples | Module calls | Browser sessions | Spec duration |
| --- | --- | ---: | ---: | ---: | ---: |
| firefox3 | 92.0.1 | 16 | 20 | 16 | 272.24 s |
| firefox4 | 133.0.3 | 16 | 20 | 16 | 256.83 s |
| chrome4 | 131.0.6778.204 | 16 | 20 | 16 | 106.52 s |
| edge4 | 131.0.2903.112 | 16 | 20 | 16 | 148.31 s |

All **64 examples pass**, with no pending examples or outside errors. Eighty
public module calls cover repeated check/default reads, seven text/path
variants, real HTTP, an empty-text redirect, repeated AutoCheck-disabled reads,
missing files, permission denial, unsupported blank HTML and refused connections.
Fixtures include special HTML characters, UTF-8 with a BOM, a file exceeding
32 KiB, nested paths and both nonempty/empty filenames containing spaces.
All **64 owning browser sessions** are deleted through their known IDs. No
per-call native audit has to recover a leaked session.

Profiles run serially with two task containers: target 768 MiB/0.5 CPU/512 tasks,
Framework 768 MiB/1 CPU/256 tasks. Memory plus swap equals the memory limit;
neither container is privileged. Live inspections verify these actual limits.
Firefox is headless; Chrome and Edge use the vendor virtual X display with VNC
disabled. One owning browser runs at a time. The first console has an observed
prompt and two fresh metadata snapshots with no manually seeded cache; the
remaining profiles use verified same-invocation metadata reuse.

Root verifies all **58 current selected input hashes**, native
state, actual image identities and the same Docker engine/context. Twenty-eight
independent cleanup queries verify eight exact containers, four exact networks,
project inventories and an empty global container list. No Docker volume is
created. The bounded cleanup guard removes unrelated tool containers recreated
by the app; these are not module coverage.

The final read-only evidence package has **734 manifest entries**,
SHA256 `e2ed60051188fb89d2c52b2a63bed2434164030b2e2b7c00ace5a620dbeadb1b`. Identical contents are hardlinked only inside
the package, separately from source and run files.

The first root verifier stopped because it assumed optional `Entrypoint` was
present in every vendor JSON config. All four images omit it; live and local
image inspections return null and preserve the vendor command. The corrected
comparison retains exact equality. Both verifier versions and the failed attempt
are preserved; no functional rerun or module change was needed.

## Original failures, fixes and fixture corrections

Clean original-source run `20261111T180020-3fa3b8` has **64 examples/13 failures**:
four on legacy Firefox and three on each modern browser. Its 79 module calls
produce false good/empty reads for missing, denied and non-text blank documents.
With AutoCheck disabled, legacy cleanup prints deletion while its wrong endpoint
leaves the known session active. The independent audit records and removes that
task-owned session to avoid cascading failures; the example still fails.
All native pre/post controls pass without resource exhaustion, files/processes
remain unchanged, and all 28 exact cleanup queries pass. This 699-entry seal has
manifest `d8520abafbb3e122cba135213569675617479c06fc46e7061af4a79ba7e8a311`.

The fix validates HTTP/JSON/WebDriver results and ensures cleanup of a validated
returned session ID through the compatible `/wd/hub/session` endpoint, regardless
of AutoCheck. It never discovers or deletes arbitrary sessions after a lost
creation response. Cleanup failure warns rather than falsely claiming deletion
or replacing an earlier read failure.

Chromium legitimately omits `pre` for an empty text document. The fallback uses
standard effective-URL and document-state APIs, requiring matching driver and
document URLs, an appropriate resource scheme, `text/plain` and string body
text. This preserves encoded spaces and HTTP redirects while rejecting initial
data/about pages and HTML. A nonempty HTML fixture has an exactly empty rendered
body, proving why an empty body alone is insufficient.

The identical expanded focused suite has **60/35 failures original, 60/9 on the
provisional pre-only guard, and 60/0 final** (53 module and seven existing
formatter examples). Native response provenance is retained; synthetic malformed
and recombined cases are explicitly labelled. Root independently reruns 60/0.
Syntax, helper/spec lint, docs and whitespace checks pass. Canonical module lint
retains exactly two pre-existing findings: redundant Platform and duplicate
RPORT; msftidy exits 2. Human Scenarios remain byte-for-byte unchanged.

Earlier setup failures remain separately preserved: an invalid Compose project,
an unusable internal-only host mapping, a wrong legacy native status path,
Chromium headless/X-display failures, a 256-task ceiling reached by repeated
legacy browsers, and an incorrect native assumption that every empty file has a
`pre`. The mixed PID failure and Chromium fixture assertion seals contain 342
and 527 entries respectively. Those failures are not accepted module verdicts.
The final 512-task/vendor-display fixture has zero PID exhaustion and independently
validated document metadata on every browser.

## Scope and review

**Summary:** Four genuine browser profiles qualify plaintext reads and cleanup.

**What looks good:** Every declared browser is covered with native pre/post
controls, repeated execution, negative cases and exact teardown.

**Concerns:** These Linux Grid releases do not qualify all Selenium releases,
remote providers, arbitrary binary/HTML file recovery or every browser option.
The broad module campaign remains open; the two existing lint findings remain.
Existing `druid_js`, `superset_rce_owner` and `wordpress_admin` profiles still lack
current passing results and remain excluded from the checkpoint.

**Suggestions:** Keep further browser/version extensions serial and preserve
native document controls when changing extraction logic.

An individual source-hashed ZoomEye review records its hosted-account target
requirement. Its container-keyword hit comes from “composed” in query prose.
The [official SDK](https://github.com/knownsec/ZoomEye-python/blob/c9a43400e7ad77b09fbf782c1fcc78e974103fb9/README.md)
documents authenticated hosted searches; a local invented index would not qualify
that provider contract. No provider query or account operation was performed.

Reproduce the browser labs from the Framework root:

```sh
bundle exec ruby tools/dev/run_guarded_module_target_tests.rb selenium_firefox3 selenium_firefox4 selenium_chrome4 selenium_edge4
```

Evidence is retained locally under `tmp/module-target-tests/20261111T181635-34813d/` and
the sealed `selenium-verified-20261111` package. Commit/push is to the user's
public fork branch; no PR is created.
