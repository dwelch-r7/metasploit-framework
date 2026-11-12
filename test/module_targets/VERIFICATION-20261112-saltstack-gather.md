# Salt post-module collection validation — 12 November 2026

The corrected Linux Salt 3000.1 lab is **qualified**: both declared session
types passed all twelve functional examples, including exact loot/reporting,
repeated collection, each collection flag, and a selected minion. Earlier genuine
module failures and separate setup/harness failures are preserved below.

The [lab](saltstack_gather/README.md) runs a genuine source-built Salt 3000.1
master and two minions on one Linux host. Native checks verify daemon identity,
accepted and administrative key categories, useful hostname/interfaces/kernel
results from both nodes, SLS compilation, nested pillars and generated RSA keys.
The corrected native run verifies twenty Salt files and fifteen Python runtime
packages, plus Debian's checksum-pinned `net-tools` package. No Salt application
implementation or owning module method is replaced.

| Attempt | Observed result | Classification |
| --- | --- | --- |
| Native `093946-f78b96` | Failed before collection: config alias comparison resolved only one side of `/var/run` → `/run` | Lab assertion; corrected |
| Native `094126-284ddd` | Both nodes, key categories and RSA parsing passed; compound CLI exceeded 30 seconds | Fixture timeout; changed to module's existing 120-second default |
| Native `094322-466a8f` | Returned data exposed empty interface inventory and failed compound/single-function requests despite a preliminary keys-only success label | Weak control; not qualification. Missing real network utility was a setup gap; command requests were investigated separately |
| Native `094745-01576b` | Useful native hostname/interfaces/kernel data, SLS and pillars from both real nodes; exact locked dependencies; cleanup passed | Corrected native control passed |
| Framework `20261112T095009-227646`, source `16955afb861` | Four examples/four failures; two Meterpreter and two shell sessions; native before/after passed; cleanup passed | Genuine module failures, detailed below |

Default collection failed on both session types with
`ArgumentError wrong number of arguments (given 2, expected 1)` at
`YAML.safe_load`. Inventory-only collection reached the roster, wrote null YAML
instead of roster contents, gathered the minion config a second time, then failed
importing the actual encrypted RSA key as an unencrypted SSH credential.
That validation failure stopped collection before the remaining roster entries.
The original encrypted loot and passphrase note were captured.

Real session command capture also merges CLI stderr into YAML stdout. Startup
deprecation warnings caused key-list parsing to fail. Native controls capture
stdout and stderr separately, so their success does not establish that the
module's parser accepts a real session's combined stream. The accepted-minion
table iteration has a separate capture-input unit investigation; it was obscured
by this parser failure in the initial functional run.

The original run used a genuinely cold console: prompt, BOOT receipt and both
fresh metadata snapshots were independently observed. All three containers were
capped at 1,408 MiB/1.7 CPUs in total. The manager finished with exit status 1;
all eight independent exact container/network/project/global absence queries
passed. Docker was empty afterward. No pull request was created.

Original evidence is preserved in a read-only 248-file seal, with ninety exact
source inputs. SHA-256 of `MANIFEST.sha256`:
`a325034d2a9cb4afacec4ee5386256cc1475a5d927dc45942ba9bcd09db83560`.
Every entry, file mode and single-link identity was independently rechecked.

## Fixed source and harness review

The isolated fix `7aad3e71d84c40f7e89ce907c2caa64445428d16`, imported as
`236da4190a0`, passed an identical 24-example/seed-58319 unit comparison:
24/21 failures originally, 24/0 afterward. Nine original failures are absence of
the new helper API; the remaining assertions share underlying causes. Parser,
crypto and benign host-shell framing are real; session and reporting boundaries
are doubles. New grains fixtures were explicitly synthetic in that unit suite.
The native `102715-b8507f` control subsequently verified real grains from both
nodes and twenty-two pinned Salt files, plus the locked runtime packages.
The parent independently repeated the 24 passing unit cases. Strict lint has no
new findings; six pre-existing library/module findings and five MSFtidy findings
remain. Unit evidence seal: 153 entries, SHA-256
`08ef8c83c0b1e5bad30290f7be79020abc847632e8b13418b715482084a29848`.

Fixed-source run `20261112T104521-c1de8d` completed both full six-case profiles:
Meterpreter 6/6 failures and shell 6/3 failures. Fourteen actual post calls
produced no owning-module error. Independent native controls passed before and
after both profiles. These results **do not qualify the module**: the harness's
strict Psych reader interpreted the interface's `::1` scalar as a Ruby Symbol
and rejected it, while the Meterpreter helper sent `core.shutdown` without
performing Framework's passive-dispatcher/session cleanup. The ordinary cleanup
that followed removed the processes. Three shell examples passed completely.

The corrected oracle uses Salt's pinned native safe YAML parser to preserve the
IPv6 scalar's semantics. Session cleanup now uses Framework's public `kill`
method and must prove the actual identified processes and session are gone,
with SQL closure recorded. The owning module/mixin bytes remain unchanged.
A complete corrected replay remains required.

All sixteen exact cleanup queries for the fixed-source run passed and Docker
was empty. Its read-only 653-entry seal has manifest SHA-256
`73fe117a4b6e3fbcc34ec0dd1889244417a2b6b414621e62703c16393261ec85`;
the failed build-selection run has 475 entries and manifest SHA-256
`98159b904e82bc1296270eb823685f6bf750b3184407c6c1271ebbe308bcbe28`.
Every entry was independently rehashed.

The replay uses process-scoped `DOCKER_CONTEXT=default BUILDX_BUILDER=default`.
Both `default` and the laptop's unchanged global `desktop-linux` context were
verified to reach engine `10febd11-6998-4e44-a0e9-00397e7a0624`. An isolated
BuildKit container created by an earlier unsuccessful build was removed and
its absence independently checked. No application test was run in that failed
build attempt. The canonical Dockerfiles and shared launcher remain unchanged.

## Final verified replay

Source `5177e73734d6794f5565d2506ae94a972a1b0c9c`, run
`20261112T110616-13459e`, completed with actual manager exit **0**.

| Profile | Functional examples | Owning post calls | Real sessions with SQL closure | RSpec seconds |
| --- | ---: | ---: | ---: | ---: |
| Python Meterpreter HTTPS | 6 passed, 0 failed | 8 | 6 | 301.772152 |
| Unix command shell | 6 passed, 0 failed | 8 | 6 | 293.613325 |

Both profiles have zero pending or outside errors and unchanged exact source
inputs: 93 per profile, 95 distinct. Native checks passed before and after both
profiles; daemon identities, configuration, generated input files, administrative
key lists and dependencies remained stable. Default and inventory collection ran
twice on the same session. Individual hostname/interface/OS flags and selection
of minion A were checked on both session types.

The checks require exact local minion configuration, all four key categories,
both selected node responses, compiled SLS blocks, roster and nested pillars.
Original plain/encrypted key loot matches native file hashes. Three credential
identities produce four Untried SSH logins, including reuse of one plain key;
decrypted credential keys match the native public key material. Passphrase notes
and real host records are verified, with disabled fields preserving existing
metadata. This is inventory collection, not SSH authentication.

Before and after collection, genuine session APIs prove root execution, daemon
role/token, actual PID identity and file contents. Public Framework termination
removes the identified processes and sessions; SQL records prove closure. No
cleanup proof error remains. The first console's cold prompt/BOOT/two fresh
metadata snapshots were independently observed. The shell profile used only the
normal cache produced earlier in that same invocation.

All sixteen independent exact resource and global absence queries passed. Docker
was empty after teardown. The 692-entry read-only evidence seal has manifest
SHA-256 `5d2a8ed238e5a1cead0e2e8a51300cd45493776588296ca16a6420dac67cb916`;
every entry, mode and single-link identity was independently verified.

The campaign checkpoint now contains **212 qualified modules, 195 profiles and
2,068 functional examples**. The broader module campaign remains incomplete.
No pull request was created.

## Review

**Summary:** the corrected source and complete twelve-case Linux replay pass;
the original and intermediate failures remain independently preserved.

**What looks good:** real native controls, exact collected evidence, actual
credential persistence, both session types, repeats, flags, selection, metadata
retention and physical/session/database cleanup. No source method is replaced.

**Concerns:** qualification covers root sessions on Linux Salt 3000.1 with
co-installed roles and generated RSA keys. Other versions, operating systems,
separate hosts, unprivileged sessions and other key formats remain unqualified.
Remote minion configuration collection and actual roster SSH authentication are
not established. The previous published head `2e8019e7ae4` finished CI with 62
successes, one skip and one Windows Meterpreter TCP/UDP send-timeout failure
([job](https://github.com/dwelch-r7/metasploit-framework/actions/runs/43192122040/job/131093797086));
its cause is unverified and this local replay does not clear that failure.

**Suggestions:** continue the remaining Docker-feasible owners, including the
local Salt minion deployer using independent deployment/cleanup controls. Inspect
the new publication's CI separately; do not infer broad platform correctness
from these two Linux profiles.
