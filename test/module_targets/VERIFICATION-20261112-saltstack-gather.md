# Salt post-module collection validation — 12 November 2026

The module remains **unqualified**. Both real declared session types reproduced
module failures after independent native controls passed. Source fixes and
stronger functional replay are in progress; registration is not a passing result.

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

## Review

**Summary:** genuine module errors reproduced; no passing module claim yet.

**What looks good:** real daemons and native controls, original failure captures,
both declared session types, isolated state and independently checked cleanup.

**Concerns:** fixes, exact semantic assertions, repeated collection, flag and
selector paths still require a complete replay. Linux co-installed roles only;
other versions, operating systems and separate hosts remain unqualified. Roster
credentials are inventory fixtures, with no real SSH authentication claim.

**Suggestions:** complete capture-derived fixes in a separate worktree, then
require exact loot, credential/reporting, native state and session cleanup before
qualifying this owner.
