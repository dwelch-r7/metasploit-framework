# Grafana SQL expression qualification

The integrated checkpoint is **177 runtime modules, 115 qualified families and
1,393 functional cases**, with current recorded inputs and passing teardown.
The new four-profile corpus qualifies selected Grafana 11.0.0 Linux command
and Bash paths. Grafana 11.0.5 command delivery remains under investigation.

```sh
nice -n 10 bundle exec ruby tools/dev/run_guarded_module_target_tests.rb grafana_expression grafana_expression_fixed grafana_expression_stock grafana_expression_anonymous
```

## Actual results

Invocation `20261110T181514-2d413b` naturally exits zero with **14/0** examples,
zero pending/outside errors and passing cleanup for every profile:

| Genuine profile | Cases/failures | RSpec seconds |
| --- | ---: | ---: |
| 11.0.0 authenticated Viewer | 7/0 | 150.376258 |
| 11.0.5+security-01 | 2/0 | 21.045663 |
| 11.0.5 without DuckDB | 2/0 | 18.551041 |
| 11.0.0 Anonymous Viewer under `/observability/` | 3/0 | 123.802927 |

The 34 owning console calls cover safe file-read checks, four exact quoted UTF-8
command outputs, four used Bash sessions, credential-shape/authentication
refusals, unrelated Apache and genuine fixed/missing-binary failures. Two
separate generated-payload/handler/native-target calibrations precede positive
profiles. All six sessions execute exact commands as UID472, prove a live native
PID, receive target exit, reach native PID absence and then close the host session.
Four sessions belong to the owning exploit. Generic output-file removal is
explicit operator cleanup; owning sessions exercise FileDropper. All fourteen
original examples and 34 main/hook assertion expressions remain strict.

Mandatory native gates record 107 CLI calls and 68 HTTP requests; 86 component
direct-CLI ledger entries remain separate. Vendor ancestry, installed CLI/engine,
actual service HOME/cwd, signed-extension enforcement, scalar/file data,
roles/authentication and logical/cache restoration are checked. The copied A/B
batch remains an algorithm diagnostic; native marker observation is independent
of Framework execution.

## Source and fixture attribution

The owning repair, already published as `fb3ff20470e`, changes only `.to_json.b`.
The captured UTF-8 request sent 4,567 bytes while declaring 4,566. Matched real
module/Rex emission examples reproduce 2/1 before and 2/0 after; ASCII body
length is unchanged. Shared Rex/core code is unchanged.

Earlier 11.0.5 delivery reaches a distinct SELECT-only serializer error. Legacy
baselines separately expose foreground session dispatch and an invalid file
transfer prerequisite. Public `run -z` now applies only to owning Bash calls.
Calibration creates exact stdin bytes as UID472 under umask077/noclobber, then
requires native owner472/mode600/identical SHA before launch. The failed copied
file's owner/mode were not captured and remain unknown. No target security,
parser or startup change, recovery command, manual metadata seed, deadline
extension or production algorithm substitution produces the pass.

The fixed profile is the independent 11.0.5/security-01 comparison, not the
patched counterpart to 11.0.0. Other declared release paths, OS/architectures,
roles and payload/delivery families remain unqualified. Existing human module
documentation bytes are unchanged; the lab link is appended.

## Parent verification and resources

The parent recomputes four actual runner maps: 73/75/75/75 inputs, union82.
It imports and byte-verifies all 233 invocation files, including eight disposable
bootsnap-cache files excluded from the worker export. All 362 export entries
verify; manifest SHA256 is
`206d7eb63c80b58c3feddf4367b0f837c0579bb09f78b5ac1f01047c5fd8edb1`,
under `/Users/dwelch/.codex/reports/grafana-expression-final14-20261110-2d413b/`.
Parent two-file Ruby lint, module-document checks and two Python AST checks pass.
Lifecycle records distinguish two calibrations from four owning sessions.
Receipts are `tmp/grafana-expression-parent-input-audit.json`,
`tmp/grafana-expression-parent-lifecycle-audit.json` and
`tmp/grafana-qualified-parent-terminal-audit.json`.

Each serial project uses exactly three containers with actual total limits of
1,856MiB/2.5CPU. The first real prompt, isolated BOOT and both fresh atomic metadata
snapshots were observed; later profiles use ordinary within-invocation reuse.
Parent 29 fresh Docker queries confirm all twelve containers/four networks
absent, twelve project-label inventories empty and global Docker empty. The
worker's original network-error observer and reviewed derivative are both kept;
that observer correction does not rerun a target or alter the fourteen results.
All prior failures remain in separate immutable lineage. The broader campaign
remains active and incomplete.
