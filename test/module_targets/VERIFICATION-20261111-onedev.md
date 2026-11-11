# OneDev verification — 11 November 2026

The checkpoint is **203 qualified modules, 162 profiles and 1,757 passing
functional examples**. The [OneDev lab](onedev_file/README.md) adds genuine
affected, fixed and unrelated targets for `auxiliary/gather/onedev_arbitrary_file_read`.
The campaign remains incomplete: 298 documented container hints need review,
alongside unhinted candidates. Registration of 205 sources is not qualification.

## Targets and result

The vendor [advisory](https://github.com/theonedev/onedev/security/advisories/GHSA-7wg5-6864-v489)
identifies 11.0.8 as affected and 11.0.9 as fixed. Platform manifest/config
digests and pinned release commits are in [profiles.json](onedev_file/profiles.json).
The normal vendor entrypoint, upgrader, JVM wrapper and HTTP handlers remain in
use. Native version responses confirm both running releases. Root compares the
actual image IDs, layer identities and commands with the vendor image configs.
No Docker socket, executor, CI build or external database is required.

Final source: `69a884b8cc5284495ec2f3ba075b6f954aa40ea1`.
Run: `20261111T201452-3a9d45`. Manager and all three live observers exit zero.

| Genuine target | Examples | Failures | Spec seconds |
| --- | ---: | ---: | ---: |
| OneDev 11.0.8 | 26 | 0 | 110.87 |
| OneDev 11.0.9 | 11 | 0 | 53.81 |
| Apache 2.4.62 control | 2 | 0 | 15.40 |

There are no pending examples or outside-example errors. The first console has
an observed prompt, BOOT record and two freshly generated metadata snapshots,
without a seeded first cache. Subsequent profiles use only the normal same-run
metadata seed, independently observed and compared byte for byte.

Native clients verify accepted/rejected administration authentication, private
project creation, anonymous access enabled/disabled, project lookup and ordinary
published-site content. Actual filesystem reads independently establish the
expected file bytes. Both releases exercise the real traversal path: affected
reads match those bytes; fixed reads return HTTP 500 with `Invalid request path`.
Missing files, directory redirects and the owning UID/network namespace's
refused port have independent controls.

The 65 public module calls cover check classifications, explicit project and
wordlist discovery, AutoCheck enabled/disabled, stdout/loot, negative paths and
repeated execution. Root independently verifies all 18 successful stdout bodies
and all nine actual loot files against native bytes. Content includes empty,
Unicode, spaced-path, large, error-phrase and explicitly generated five-byte
binary cases. Fixed and unrelated targets create no loot. Hidden fixed versions
return Unknown; visible fixed versions return Safe. Affected private reads prove
Vulnerable; public version detection supports Appears.

Native pre/post controls preserve file bytes, JVM identity, project/security
state and the unrelated Apache process/body. All memory/PID event counters stay
clean. Every selected input remains current: **54 distinct input hashes**.

## Original failures and correction

Clean original run `20261111T200547-a09a6d` has **39 examples/seven failures**:
affected 26/5, fixed 11/2, unrelated 2/0. Native pre/post controls pass, with
stable state and all 23 independent cleanup queries passing. Its read-only
422-entry seal has manifest SHA256
`ee4e70b0549d87621c08950fb94f5bfd92ddcdcce0bc95274bcc7343ba107945`.

- A directory's HTTP 200 JavaScript redirect is stored as successful file loot.
  On the patched release, AutoCheck-disabled reads store the 19-byte error body
  as successful loot in both anonymous-access modes.
- A legitimate file containing `Site file not found` is incorrectly rejected.
- A literal space in TARGETFILE produces Jetty HTTP 400, printed as successful
  file content instead of the native-proven file.
- An invalid project is interpreted as a patched product when its version is hidden.
- With anonymous access disabled, AutoCheck skips wordlist discovery and blocks
  a working file read. The same original wordlist works with AutoCheck disabled;
  it also works through AutoCheck when the public version is visible.

The correction requires HTTP 200 and the vendor's filename-bearing response
metadata before treating a body as a file. Missing files have only `inline`;
directory redirects lack file disposition metadata. Legitimate content is no
longer rejected by its text. TARGETFILE uses the existing Rex URI encoder while
the intentional traversal escapes remain unchanged. Check/run share project
resolution and expected-error handling, without changing configured datastore
values. PROJECT_NAME is optional in metadata, matching the documented wordlist
choice. An unproved hidden-version read returns a reason-bearing Unknown.

The identical focused suite, seed 45309, has **53 examples**: 46 module examples
and seven existing formatter examples. Original source exits 1 with 30 failures;
the first fix exits 1 with the new space-URI assertion failing; the final source
exits 0 with no failures. Root independently reruns 53/0 and verifies the exact
worker module/spec/capture hashes. Captured-response doubles and labelled
synthetic nullable, malformed and transport guards complement genuine acceptance.
They do not substitute for it. Human Scenarios remain byte-identical.

Helper/spec lint, syntax, documentation and whitespace checks pass. Canonical
module RuboCop exits 1 and msftidy exits 2 for the identical pre-existing
`RedundantPeerInPrint` finding. This module has HttpClient without the Tcp/scanner
prefix, so the retained explicit peer is not redundant; no new finding is added.

## Fixture corrections and resource limits

Earlier runs exposed fixture errors, preserved separately from module failures:
the vendor requires a disposable `/opt/onedev` data volume; its version API returns
bare text; directory redirects use HTTP 200 JavaScript, not HTTP 302. Wordlist
constants needed explicit qualification, and the missing-wordlist case needed to
accept Framework's expected public OptPath validation before module execution.
The shared console runner remains unchanged.

The first mixed batch's fixed wordlist errors were initially misclassified as
required-PROJECT_NAME validation. They were actually unresolved test constants.
The preserved addendum corrects that classification: 28 fixture failures and two
module failures. Clean live replay shows required metadata does not itself block
the original public wordlist path; its real failure is hidden-version AutoCheck.

The unrelated Apache's original 64-task cap can prevent its default workers from
starting (`AH03104`/`AH02324`), causing connection refusal before any module call.
Its corrected 128-task cap and real HTTP readiness check pass native pre/post
controls with zero PID-limit events. Its memory limit remains 64 MiB.

Only one project runs at a time, with two containers. Each OneDev project is
capped at **1,536 MiB/1.5 CPUs**: target 768 MiB/0.5 CPU/256 tasks and Framework
768 MiB/1 CPU/256 tasks. The JVM has a 320 MiB heap and bounded native areas.
The Apache project totals 832 MiB/1.1 CPUs. Live inspection verifies caps, equal
memory/swap limits, loopback-only published ports and no privileged containers.
Every target is removed before the next starts.

The final 23 independent cleanup queries verify exact containers, networks,
OneDev data volumes, project inventories and an empty global container list.
The actual Docker engine/context is unchanged. Unrelated tool containers recreated
by the app are handled by the bounded task-local guard, outside target coverage.
Images and unrelated volumes are not pruned.

The final read-only evidence package has **436 manifest entries**, SHA256
`e4dc3edb321f0c8cce0789d3fb39b19110e13e6a28ef1d017217b3aa8be027b2`.
Identical files are hardlinked only within the package, separately from active
source and run files. Evidence is under `tmp/module-target-tests/20261111T201452-3a9d45/`
and the local `onedev-verified-20261111` seal.

## Review and remaining scope

**Summary:** Genuine affected/fixed checks, file collection and refusal paths pass.

**What looks good:** Native bytes, real loot, repeated calls, unchanged process
identities, current inputs and exact teardown agree.

**Concerns:** Qualification covers these two vendor releases at the root base
path, plus one unrelated HTTP implementation. Other versions/deployments remain
untested. Existing `druid_js`, `superset_rce_owner` and `wordpress_admin` profiles
remain unqualified and excluded. Inventory has 18 individual reviews and no stale reviews.

The previous published head `3e7a62c7cf3f33faad985b755dca80628f10cbf7` has a
[Mettle build failure](https://github.com/dwelch-r7/metasploit-framework/actions/runs/43084834954/job/130746391837)
and two checks still running at inspection. Job metadata/log retrieval returned
HTTP 502 on both attempts; the cause remains unverified. This check predates the
OneDev commits. New-head CI must be assessed separately and is not reported green.

**Suggestions:** Keep further versions and target families serial, and retain
native response metadata/bytes when changing file classification or discovery.

Reproduce from the Framework root:

```sh
bundle exec ruby tools/dev/run_guarded_module_target_tests.rb onedev_11_0_8 onedev_11_0_9 onedev_unrelated
```

Publication is to the user's public fork branch. No PR is created.
