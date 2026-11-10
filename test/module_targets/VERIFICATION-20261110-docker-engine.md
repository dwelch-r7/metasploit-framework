# Docker Engine information qualification

The selected checkpoint covers **133 runtime modules, 66 families and 902
functional cases**, adding one scanner and ten cases to the
[Fetch requalification](VERIFICATION-20261110-fetch-lifecycle.md). Exact counts,
current recorded inputs, zero failures/pending/outside errors and owned teardown
hold for every selected result. The campaign remains active; no PR or full local
RSpec suite run. Capture/IMAP, Flink and Jolokia work remains separate.

## Genuine targets and results

The [Docker Engine lab](docker_engine/README.md) runs official digest-pinned
Linux amd64 Docker 26.1.4/API 1.45 and 28.0.4/API 1.48 daemons with vfs, no bridge,
iptables or forwarding. They drop SYS_ADMIN/SYS_TIME, gain no extra capabilities
and mount no host socket/system filesystem. Their own Unix sockets/data volumes
belong only to their containers. No nested workload or escape is attempted.

Real Apache gateways provide Basic auth and TLS. Native TLS verifies its actual
fixture certificate and destination name. These are gateway policies, not daemon
authentication features. Each run requires nine independent native commands and
ten HTTP controls: actual Docker client/version/info/capabilities, accepted and
rejected auth, TLS and unrelated HTML/200/404. HTTP/CLI documents agree after
only the CLI's component build-time display conversion; raw data remains.

| Invocation | Cases/failures | RSpec seconds | Classification |
| --- | --- | --- | --- |
| `20261110T010754-768b7c` | 10/10 | 120.650118 | Before first prompt/BOOT; no native suite or module ran |
| `20261110T011231-14ea41` | 10/7 | 92.378481 | Six architecture fixture expectations plus one false detection |
| `20261110T012801-c747e1` | 10/1 | 122.69302 | Corrected original; all twelve positive executions pass |
| `20261110T014353-459e96` | 10/0 | 87.315124 | Final 57 current inputs and owned teardown |

The original fixture expected raw `amd64` in `Mdm::Host.arch`. That model
deliberately represents an unlisted vendor spelling as `Unknown`, retaining the
exact spelling in `detected_arch`. Six failures therefore reflect a wrong
expectation. Corrected assertions verify the documented fallback and both native
fields. No architecture-normalization change is made.

The remaining original failure is concrete: genuine Apache HTML/200 produces a
blank Docker version, a `docker_version` note whose version is nil and a host
with empty platform fields/blank-version info. Aggregated assertions retain
the console output and both actual SQL rows. A six-line owning repair requires
a nonblank string Version and a valid string ApiVersion in an object before
printing/reporting. Real documents and successful output/public options remain.

Final cases repeat both versions with VERBOSE true/false plus Basic/TLS paths,
then cover absent/rejected credentials and both unrelated responses. Sixteen
actual module invocations complete. Direct SQL verifies exact workspace/service
endpoints, serialized version, raw architecture fallback, OS/kernel and stable
note IDs without duplicates. Every negative leaves no host/note record.

## Verification, integrity and limits

Matched focused tests improve **21/10 to 21/0**, fourteen owning examples and
seven shared examples; parent replay is 21/0. Actual Docker/Apache bodies ground
fixtures; missing/blank/type boundaries are labeled derived. Only owning source
changes in that focused comparison. New test/helper Ruby lint 2/0 and owning spec
lint 0. Same-path original/current source lint has twenty identical inherited
findings. Legacy tidy notice and all six module-doc warnings remain unchanged;
the original human Usage console bytes remain identical.

The corrected original 50 inputs and final 57 have the same runtime assertions,
native helper/targets and guide. Seven unit/capture dependencies are explicitly
added; manifest and owning source values change. This is not an identical-key
functional comparison. Every original 50 file and initial/corrected fixture
snapshot is retained, with unchanged raw result revisions/paths.

The parent independently audits all four runner projects/twelve volumes absent.
Two native projects/five volumes are separately removed. The durable
`docker-engine-module-validation-20261110-024c5fc7053` export retains every run,
native/SQL/schema/source snapshot and separate source/lab commits. All **491**
checksum entries are reread; `SHA256SUMS.json` digest:
`a43d76125325b784b44fd2eb3971d1aba6aa53e6a118b11e92baa706fea4cb70`.

Linux amd64 information gathering is qualified. Windows, other CPUs/releases,
mutual TLS, arbitrary authorization plugins, container creation and daemon
privilege-escalation/cron modules remain unqualified. Public fixture accounts
and generated certificates have no external trust. Startup failure is retained
without attributing a cause or increasing timeouts. Declared inputs are not the
complete dependency graph. Aggregate selection is
`tmp/module-target-checkpoint-docker-current.json`; known WordPress admin and
Ansible deployment limits remain separate investigations.
