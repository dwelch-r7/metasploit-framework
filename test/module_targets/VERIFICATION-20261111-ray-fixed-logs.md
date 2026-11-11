# Ray log API fixed-release comparison, 2026-11-11

The checkpoint is **190 qualified modules, 136 profiles and 1,506 functional
examples**. This adds one fixed-release profile and seven examples; the affected
profile was replayed against its current inputs. Registration remains 192 sources,
with 312 documented container hints pending review. The campaign is incomplete.
The production module is unchanged. No PR is created.

The [affected profile](ray_logs_enum/README.md) and
[fixed profile](ray_logs_fixed/README.md) use genuine single-node Linux Ray,
unrelated Apache and the canonical Framework console. Each serial pipeline has
three containers, capped at 5,952 MiB and 2.1 CPUs. Ray retains its normal full
dashboard, one CPU, a 5,120 MiB cap and 1,536 PID/thread slots. Application
handlers, capabilities and daemon settings are unchanged.

## Identity and preserved prerequisite failures

The official 2.57.0 amd64 image is pinned to
`sha256:0efd29764b34ceaeee8b5b91c72d34bfea56ba3f31cfa3eeb882d63f33988b06`.
Its installed wheel and image label report
`4464bbb6e21bce4893ed3396b2e33996188d511d`, one commit behind release tag
`878455a3d8f5bcea569d8c40a39b7b5681a55125`. The intervening commit changes only
`doc/source/ray-overview/pip_freeze_ray-py310-cpu.txt`. Eleven installed source
files match independently fetched official bytes at both revisions. The manifest
records the installed identity and release tag separately.

The [upstream fix](https://github.com/ray-project/ray/pull/64701) rejects absolute
glob paths and parent-directory components in the genuine log-agent gRPC service.
Two initial native failures ran no Framework module, terminated and passed eight
independent exact-resource cleanup queries before selected inputs were changed:

| Native run / source | Observation | Sealed files / checksum-manifest SHA256 |
| --- | --- | --- |
| `100700-8d7688` / `1ee460214d0` | Identity gate stops on installed/tag commit mismatch. Eleven selected files subsequently proven identical at both official revisions. | 105 / `573d5210c6a0dd910885d3a18a3e52642ba9c771c144c9d86a646dfa16de4243` |
| `101014-c84125` / `a42eb6716a9` | Identity, task and ordinary SDK access pass. Probe incorrectly expects detailed rejection in HTTP body; Ray emits generic 500 while StateHead records the precise gRPC error. | 102 / `f10ef2d9b3763eac059ac4e43737977d844075e87fe269b356603fc41bff2d34` |

Neither failure establishes a module defect. The corrected native control uses
the installed GCS client to resolve the actual registered agent and its generated
gRPC client to list an ordinary log, then requires nine exact `INVALID_ARGUMENT`
rejections. Every corresponding HTTP 500 must match its actual glob and precise
error in the genuine StateHead log. A generic HTTP failure alone cannot pass.

Native run `101259-115be4`, source `606ff07a7b8`, passes eleven source hashes,
a scheduled task returning 42 as UID1000, ordinary SDK listing and exact log
retrieval, the gRPC positive/nine denials and twelve HTTP controls. Fixture bytes
remain unchanged and owned paths are removed. The manager exits zero, capture
errors are empty, inputs remain current and root observes the actual two-role
runtime before eight exact cleanup queries pass. Its immutable 105-file package
has manifest SHA256
`3da4dbd3112195e3a75c7728b9dbeb9ce4e4110a4ef331f27da5e8c1014f4f7c`.

## Owning module results

Guarded invocation `20261111T101404-6a12fe` runs both profiles serially from
source `2e640bc3f6d9bf75260171a1f859392cc6acc8ce`. The actual manager and
independent observer both terminate zero. There are no failures, pending examples
or errors outside examples.

| Profile | Examples | RSpec seconds | Exact new loot files | Current inputs |
| --- | ---: | ---: | ---: | ---: |
| Ray 2.56.0 affected | 11 | 68.459785 | 14 | 48 |
| Ray 2.57.0 fixed | 7 | 28.658800 | 2 | 50 |

The affected replay retains traversal, discovery, encoding, wildcard,
empty/missing-file, node, AutoCheck and loot cases. The fixed profile checks Safe
and automatic refusal repeatedly, then disables AutoCheck to prove denial of eight
traversal patterns on repeat and an absolute path to an existing outside file.
Ordinary relative-log enumeration still produces exact new loot twice. Unknown
node and unrelated-service controls remain separate. This establishes module
path enumeration, not arbitrary file-content retrieval.

Both profiles require native controls before and after module calls. Actual owner
fixtures persist throughout those calls, their bytes are verified, and they are
removed afterward. Fixed native phases each include eleven source hashes,
ordinary SDK retrieval, nine typed gRPC denials and nine matching server errors.
Affected phases retain nine SDK patterns and eleven direct HTTP controls.

Root observes the actual three-role limits and first cold prompt/isolated BOOT
with two fresh metadata snapshots. The second family uses that invocation's
genuine cache; seed, current files and snapshots match the first observed hashes.
No first-family seed is supplied. All 139 parent-run regular files are imported
unchanged, and all 54 distinct selected inputs match current primary sources.
Original result bytes and worker paths are preserved.

Target memory peaks are 4,385,497,088 bytes on 2.56.0 and 4,054,847,488 bytes on
2.57.0. PID/thread peaks are 883 and 890; memory/PID-limit and OOM counters are
zero. Seventeen root queries prove the exact six containers, four networks and
both project-label inventories absent, with global containers empty. No volumes
are created. The immutable 202-file whole-run package has manifest SHA256
`1e1b191de15b1c02b572ef97d043b9a6ac1dd702612fa4610781799175771e29`.

## Review and remaining scope

- **Summary:** the pinned fixed release passes alongside a current affected replay.
- **What looks good:** exact installed-source identity, working ordinary log controls,
  typed denials, persistent real owner fixtures, repeats and exact new loot.
- **Concerns:** no new code concern remains for this scope. Multi-node grouping,
  partial-node failure, other releases/architectures and custom proxy/authentication
  remain unqualified. Earlier setup failures stay preserved.
- **Suggestions:** return to the broader queue; other Ray job/profiler version
  gates cannot be inferred from this log comparison.

Primary verification includes Python ASTs, Ruby syntax/RuboCop, resolved Compose
limits, four independently rehashed installed-source maps, module-document lint,
local links and unchanged human Scenarios. No full Framework suite was run.
