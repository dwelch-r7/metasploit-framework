The client/vulnerable/fixed text files are exact output from the genuine
Go 1.19.13 linux/amd64 source-build attempt msf-minio-build-20261110t185949-d5f686.
They are metadata, not executable/binary fixtures. Their source and binary
identities are recorded in test/module_targets/minio/assets.json.

The dirty-revision/architecture and Dockerfile failures in the contract spec
are derived boundary cases, not captured native service responses. The
teardown test injects an observer failure without invoking Docker. No MinIO
HTTP/S3 target is simulated and none of these examples qualifies a module.
Buildx descriptors follow the documented text shape and are derived unit data,
not captured builder output. Filesystem conservation and Python housekeeping
examples use explicit temporary data/mocked command scheduling; they do not
execute Docker/mc or fabricate a genuine native service response.

The complete original source archives, build receipts, binaries, resource
proof and exact teardown remain in the immutable 234-entry source-build seal:
minio-source-build-20261110-d5f686
SHA256SUMS 80dfd57b1dae65bec1042bcddab528bb5e046e6581e426669e8c8ea7f4e1f20f.

`admin-info.json` is the exact successful `mc --json admin info lab` stdout
from command index 26 (zero-based) in the genuine vulnerable native attempt
msf-minio-native-20261110t231347-21bc9f. Its 6803 bytes have SHA256
db597c2d899246f8ce23b2e28f60e2852d4181c226dc802edf644eb4c3fb048f.
The raw native-control.json SHA is
701425c52924846ed751dbec5536ecc5b55cde1c745c46971227b8e2ae2cbf26;
the immutable 139-entry failure seal is minio-native-server-state-failure-20261110-21bc9f,
SHA256SUMS 6756c06081b527980e5a21b74dd35b2254972f5307ac4e97d851abcbcd425aea.
Credential fields were already redacted by the target; no fixture bytes were
rewritten. Both authentic servers report `online`; their drives report `ok`.
The pinned vulnerable server's
[local property](https://github.com/minio/minio/blob/0ff931dc765d5d8fdddcdf7687fec1b0b194fca9/cmd/admin-server-info.go)
and [peer property](https://github.com/minio/minio/blob/0ff931dc765d5d8fdddcdf7687fec1b0b194fca9/cmd/notification.go)
use madmin.ItemOnline, distinct from drive state.

The parser contracts replay that captured response and stop with a sentinel
before the HTTP quorum request. Negative cases change only the named field.
They do not simulate a successful HTTP request, format read, S3 operation,
restored snapshot or module qualification.

`missing-proof-rm.json` is the exact 194-byte error stdout from command index52
in genuine native attempt msf-minio-native-20261110t233802-58520c: the pinned
client returned1 for `rm --force` on a proof already removed by the main loop.
Its SHA256 is 4d23a6ccf86f20bc5bcd9c08d7a9875e17244e95b13c1f0e64094634cab0dbd8.
The immutable142-entry cleanup-failure seal has SHA256SUMS
cf0d4b08bf494822bc6dc18755ee6af765efd6ff7a7a452e1853976a1c0753cc.
Pinned mc [removeSingle](https://github.com/minio/mc/blob/88896ae495128646081d8f809b8934c74cb90194/cmd/rm-main.go#L279)
returns stat errors; its force/no-objects exception belongs to another branch.
The [listing producer](https://github.com/minio/mc/blob/88896ae495128646081d8f809b8934c74cb90194/cmd/ls.go)
uses successful file/folder rows and keys relative to a trailing-slash target;
zero entries emit zero rows, while listing errors fail the command.

Cleanup contracts use that real missing-object error and explicitly derived
listing rows/logical state. They test exact owned-key scheduling, error retention,
non-force bucket removal and unchanged restoration/config/proof gates without
claiming successful live S3 cleanup or providing a fake target service.

The `bootstrap-vulnerable.json` and `bootstrap-fixed.json` documents are actual
node1 HTTP records, extracted without changing fields from the separately sealed
native successes `minio-native-vulnerable-success-20261110-f9e237` and
`minio-native-fixed-success-20261110-d85584`. The local task credentials and
sentinels are intentional fixture data. Their status/body/headers are genuine;
unit contracts wrap them in the source-defined HttpLoggerSubscriber format to
exercise trace parsing. That wrapper is source-derived and is not claimed as an
actual Framework console capture. No bootstrap owner, Framework session or SQL
success is implied by these native captures.

`node1-resource-inspect.json` selects the unmodified Config.Labels and six
HostConfig fields (Memory, MemorySwap, NanoCpus, PidsLimit, Privileged,
PortBindings) from the actual node1 final inspection in the vulnerable success
above. It exercises real configured limits and the absence of direct published
ports. Selection makes it a resource fixture, not a complete container inspect
or proof of an unexecuted five-service functional lab.

`spec_discovery.rb` is an isolated registration contract, not a replacement for
the real acceptance helper. The full helper loads Framework through other shared
contexts, so this fixture uses only the genuine pure module-target/datastore/wait
helpers and TestProf DSL. An unbundled child avoids Framework gemspec metadata
preloads; require/spawn guards reject Framework loading or process execution.
It only dry-loads/registers or excludes examples, never their runtime hooks. The
four cases establish absent-runtime loading and configured 18/3 registration;
they do not prove console, Docker, native or owner execution.

The session identity negative cases use explicit `proc_pid_stat(5)` field data
(PID, state, parent and field22 starttime), with owned UID/GID/executable values.
They cover PID reuse, wrong owner/group, zombie/stopped state, unrelated executable
and PID1 without an environment marker. They are protocol-derived pure contracts;
no historical pre-exec stat capture has been invented or retrofilled.
