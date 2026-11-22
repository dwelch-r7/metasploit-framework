# LinuxKI genuine packages and check contracts — 2026-11-22

Three serial profiles pass **11 examples, zero failures, zero pending**, with
zero errors outside examples. The complete valuable feasible-module goal remains
active. This milestone qualifies Unix command execution and check behavior;
it adds no session coverage.

| Profile | Final result | Independent prerequisites and observed owner behavior |
| --- | --- | --- |
| `linuxki` | 4/0/0 | Genuine 6.0-1 package/CLI/ABI/PHP; UID33 shell and HTTP byte proofs; actual Vulnerable check; four owning ASCII/quoted Unicode/CRLF commands, repeating each on the same selection |
| `linuxki_fixed` | 3/0/0 | Genuine 6.0-2; exact effects rejected with a valid timestamp and with the owner's omitted timestamp; actual Safe check and two default AutoCheck refusals without entering the exploit body |
| `linuxki_errors` | 4/0/0 | Positive native command gate, real Apache404, actual denied-directory403 and independently refused target socket; all return reason-bearing Unknown |

Run from the Framework root:

```sh
MODULE_TARGET_NAMESPACE=my-linuxki-lab bundle exec ruby tools/dev/run_guarded_module_target_tests.rb linuxki linuxki_fixed linuxki_errors
```

## Genuine target and native controls

The fixture downloads the vendor DEBs at immutable revisions and verifies their
SHA256 before installation. The affected revision is
`5b04f4b36fd85593cea628f04886a2f1dc6df68e`; the fixed revision is
`10bef483d92a85a13a59ca65a288818e92f80d78`. Exact package, installed page and
CLI digests live in [vendor.json](linuxki/vendor.json). No opaque package binary
is added to the repository.

The observed target is Debian11/x64 with PHP7.4.33/Apache and
`libncurses5 6.2+20201114-2`. Actual CLI linkage, source hashes and usage output
are gates, not assumptions. `kiinfo -help` genuinely writes to stderr and exits10.
The ordinary package installer reports that the optional LiKI kernel module
cannot be built without matching headers. This unprivileged web-component lab
does not load modules or validate live tracing/report rendering.

Before each owning command, the identical command independently writes exact
bytes under `www-data`, then through the genuine `kivis.php`. Physical file bytes,
UID33 and absence after removal are required. Both valid-timestamp and omitted-
timestamp paths are tested. Missing trace captures or shell errors are not the
execution oracle. The native fixed control supplies `1111_1111`, reaches the
page's numeric `pid` sanitation and proves no effect. The owner's omitted
timestamp separately reaches the fixed page's early rejection.

The owning Unix target uses the actual `cmd/unix/generic` payload. The first run
uses AutoCheck; the repeat disables AutoCheck on the same selected module. The
native-proven proof path starts absent, exact bytes/UID are checked after owning
execution and the test removes the proof in `ensure`. `AllowNoCleanup=true`
passes FileDropper's compatibility gate for a generic payload/disabled handler;
physical cleanup is still required. Passive TracePoint events retain actual
commands, requests, responses and exploit-body entry.

## Confirmed repair and frozen comparisons

The original positive profile passes4/0 and the original fixed profile passes3/0.
After positive native readiness, the original error profile fails its three
check cases: actual403/404 and a refused socket abort through `fail_with` and
produce no CheckCode. A second frozen original run reproduces **4/3/0**.

A separate worktree repairs only the owner and adds focused units. `check`
returns reason-bearing Unknown for missing responses, unexpected HTTP statuses
and expected transport exceptions. The command helper lets callers handle those
exceptions; `exploit` preserves Unreachable failures and developer logging.
The four exploit delivery branches have unit coverage for that failure contract;
their successful session/delivery paths remain unqualified here.

The final frozen error comparison changes **4/3/0 to4/0/0**, and its sole changed
declared input is `modules/exploits/linux/http/linuxki_rce.rb`. All three final
profiles then pass11/0/0. Both target and Framework images have identical root
filesystems and runtime configuration; their unique Compose project labels
differ. Source hashes:

```text
original   8c2c89d7d06e8d250c7b51cb51ec95bb2b465d914ef7ef69404d02ed9943ece4
candidate  0bd446462ada508efcc94dc4f467a2b1710666333bbf38f70158eec60c6ee2b9
```

Frozen units improve **22/8 to22/0** with the same spec; the parent repeats22/0.
These totals contain15 LinuxKI cases and7 formatting examples loaded by existing
RSpec configuration. Unexpected302/500 and raised transport exceptions are unit
boundaries; the container error cases are actual403/404/refused transport.

## Retained setup and tooling results

Earlier failures remain separate from module defects:

- The first native probe checked an unindexed Apache root (403); the corrected
  readiness URL uses the genuine page. No owner was called in that probe.
- The first functional matrix inspected CLI help on stdout only. Its native
  gate failed and withheld owner calls; the real output is stderr/exit10.
- The next invocation omitted FileDropper's `AllowNoCleanup` prerequisite.
  Native controls and both checks passed, but the compatibility gate prevented
  exploit-body entry. The corrected invocation is replayed above.
- An initial source-unit oracle incorrectly read the exception's reason; the
  valid baseline reads `mod.fail_reason` and is retained separately.

Changed fixture Ruby passes lint. The owner/spec comparison has zero new lint
offenses and four identical inherited default-payload findings. Module msftidy
output is byte-identical before/after (both exit2). Module-doc tidy has six
identical inherited inline-backtick warnings (both valid baseline/candidate exit1)
and zero new findings. Syntax and `git diff --check` pass. Existing human-written
Scenarios are preserved.

## Retained qualification and cleanup

The retained set reaches **345 cases /78 profiles /801 current inputs**. All783
previous runtime inputs remain byte-identical. Ordinary actually used/closed
sessions remain327, with21 separate source-variant sessions; this milestone does
not count commands or refusals as sessions.

Every lab has one capped target and one capped Framework console. The final
profiles have zero OOM/PID-limit events. Wrappers record a two-container peak,
exact IDs and verified removal after each profile, including failed attempts.
The post-agent global inventory
also exposed two automatically initialized unused GitHub/AWS connector helpers;
both exact IDs were removed and independently checked absent. They had no mounts
or task-owned networks. No image/cache pruning or daemon restart was performed.

Both Docker contexts finish globally empty, including stopped containers.
All **37 new /1,206 total recorded container/network/volume identifiers** are
verified absent. No new global volume remains.

Evidence is indexed by `tmp/linuxki-feasibility/QUALIFICATION.json`,
`COMBINED-QUALIFICATION.json`, `CLEANUP.json`, `FROZEN-ORIGINAL.json`,
`AUTOMATIC-HELPERS.json` and the publication/checkpoint/seal receipts. The original
frozen wrapper is `functional-20261122T094508`; the final serial wrapper is
`functional-20261122T094951`, under `tmp/invoiceshelf-feasibility`.

PHP memory/dropper, default Bash sessions, Linux x86/x64 droppers, other target
releases, kernel tracing and additional network/delivery branches remain open.
No PR was created.
