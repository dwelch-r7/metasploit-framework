# NFS and RPC module qualification, November 10

The `nfs` profile qualifies `auxiliary/scanner/nfs/nfsmount` and
`auxiliary/scanner/misc/sunrpc_portmapper` against genuine UNFS3 0.11.0 and
rpcbind. The [target guide](nfs/README.md) records pinned sources, native clients,
setup, reporting and limits.

```sh
bundle exec ruby tools/dev/run_module_target_tests.rb nfs
```

## Results and repair

| Invocation | Cases | Failures | RSpec seconds | Inputs |
| --- | ---: | ---: | ---: | ---: |
| Original `20261110T030027-446040` | 18 | 6 | 165.707794 | 46 |
| Worker final `20261110T030925-f57e2b` | 18 | 0 | 179.145151 | 47 |
| Integrated replay `20261110T032809-b8b5a6` | 18 | 0 | 153.962560 | 47 |

All runs completed naturally and passed teardown. Both final runs have zero
pending examples or outside-example errors. Every integrated replay input is
current. The final corpus executes the actual modules 36 times across TCP/UDP,
ordinary/nonblank HOSTNAME/outside LHOST, heuristic bypass, denied/empty exports,
unrelated RPC and repeated reporting. It verifies 72 file-state snapshots,
38 unique service rows and eight exact export notes, preserving row IDs on repeat.

All six original failures concern two genuinely unrestricted exports whose wire
group name is the literal `<anon clnt>`. Native access and the official UNFS3
parser establish its zero-prefix, all-client meaning. The existing helper accepts
`*` but misses this implementation-specific marker. The narrow repair adds an
exact match while preserving its boolean shape and existing address, hostname,
CIDR, mask, empty-list and bypass behavior. The identical focused corpus changes
from 20/2 to 20/0; the parent independently passes all 20 examples.

The integrated helper additionally has eight YARD/comment lines documenting that
mountability is a location heuristic, not a mount/access test. Removing precisely
that block reproduces the worker's source bytes. The parent replay above tests
the documented integrated source. No RPC transport or production module changed.

## Native controls and attribution

The official UNFS3 archive SHA-256 is
`42ef63cd949b65a4ead30bee269703059a8c4269bef6aa1533215ad1c2a26d6f`.
Native gates record 111 CLI operations and 14 independently decoded RPC replies:
real `rpcinfo`/`showmount`, libnfs reads/listings/writes, exact read-back and
restoration, read-only `NFS3ERR_ROFS` and denied `MNT3ERR_ACCES`. Separate empty
and unrelated rpcbind services prevent status-only success.

Early preparation failures are retained separately: an independently reproduced
package-mirror failure, missing protocol/service tables, and unsupported literal
`*` export syntax. Native diagnostics support their fixture corrections before
any module verdict. Optional split-record RPC reached peer EOF and remains
unqualified; it is not attributed to Framework. Outside LHOST and HOSTNAME cases
test the heuristic, not native access from those identities.

No host/kernel mounts, host sockets, host networking or privileged containers are
used. Native inspections verify absent SYS_ADMIN/SYS_TIME. Worker audits cover
six owned projects and three recorded volumes; the parent independently checks
its replay project and one recorded volume absent. Cached images remain reusable.

## Evidence and limits

The unchanged worker export is
`/Users/dwelch/.codex/reports/nfs-module-validation-20261110-1680432d7f7d`.
The parent re-read all 350 checksum entries; `SHA256SUMS.json` SHA-256 is
`482aedd50a03b20b08289837970071cc80280101f2d0cac881daf51433ab8d67`.
It retains actual wire, native failures, frozen before/final inputs, source-only
focused comparisons, both complete invocations and cleanup receipts. The
[integrated checkpoint](VERIFICATION-20261110-nfs-reader.md) links the separate
parent replay seal. Raw evidence stays outside Git.

Changed specs lint clean. The helper retains exactly its inherited optional
boolean-parameter offense. Both module guides retain identical existing tidy
diagnostics and byte-identical human Scenarios. This qualifies ordinary IPv4
MOUNT v1 EXPORT and PMAP v2 DUMP on this Linux profile. UDP file I/O, kernel NFS,
NFSv4, other servers/platforms, IPv6, Kerberos, hostname ACL resolution, UID
permission matrices and fragmentation remain unqualified individually.
