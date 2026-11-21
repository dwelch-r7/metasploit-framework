# dizqueTV command execution and fixed refusal

Two [dizqueTV profiles](dizquetv/README.md) pass **10 examples / zero failures /
zero pending**. Six actual Linux commands exercise COMMAND and generic-payload
delivery, with native exact-command counterparts before every run. Fixed-release
checks and repeated AutoCheck refusal preserve all state. Production module
source is unchanged; no PR is created. The full module-inventory goal remains
active.

## Native application and prerequisites

The publisher's images are pinned to architecture-specific digests. Their
unchanged compiled application binaries are independently fingerprinted in
[vendor.json](dizquetv/vendor.json). The real API reports dizqueTV **1.5.3** or
**1.5.5**, embedded Node **v12.16.2** and FFmpeg **4.3.5**. Native command proof is
owned by UID 0, matching the stock deployment. The [publisher's fixed-release
notes](https://github.com/vexorian/dizquetv/releases/tag/1.5.5) describe the
ffmpeg-path protection; acceptance here also requires actual native denial.

Both images lack standalone Node, Python, PHP, curl and wget. Their stock Perl
core supports sockets but lacks JSON::PP and MIME::Base64. The native observer
uses the host Python standard HTTP/JSON/CSV libraries with simple Perl hex
transport for arbitrary file bytes. No extra package or application patch is
installed. A read-only Perl health probe requests the static page, avoiding the
version API that triggers command execution when the path is poisoned.

The independent controls first execute the exact shell command through the CLI,
then remove its proof. The same command next runs through the real public
settings/version APIs. Returned stdout, physical proof bytes and UID must match.
The proof is removed and absence checked before actual module delivery.

The vulnerable fixture seeds the thread count from 4 to 2. Complete API settings
and all nine root diskdb JSON stores must survive every operation, with original
factory values restored afterward. Binary fingerprints also remain unchanged.

## Maintained results

| Profile | Examples | Functional time | Covered behavior |
| --- | --- | --- | --- |
| `dizquetv` / 1.5.3 | 7 | 90.54 s | Native readiness, real Appears/Unknown checks, six commands and invalid-option guards |
| `dizquetv_fixed` / 1.5.5 | 3 | 52.17 s | Native positive/denial controls, real Safe check and two AutoCheck refusals |

Times exclude startup. The six commands are plain COMMAND, quoted COMMAND and
quoted `cmd/unix/generic` fallback, each repeated on one selected module. They
preserve single/double quotes, backslashes, Unicode and physical CRLF. A separate
generic CMD sentinel must stay absent when COMMAND overrides it. The fallback
case explicitly empties COMMAND. Each pair enables AutoCheck first, then disables
it on the repeat.

Passive traces capture original module bodies, HTTP activity, command/output
bytes and reason-bearing errors. Actual raw output must match physical UID-0
proof bytes. Both settings-update requests are inspected, including the complete
restoration payload. The original-settings instance variable clears, no Windows
upload path runs, Framework jobs/sessions empty and all database records compare
equal. Proof files are deliberately removed by the fixture after validation.
Non-session runs explicitly acknowledge `AllowNoCleanup=true`, disable the
payload handler and use zero session wait.

Zero MAXWAIT and zero POLL_INTERVAL each produce the actual BadConfig failure
before any target request. A natively refused port produces Unknown. These are
distinct from a service banner or health-only result.

The fixed API returns HTTP 400 with its specific valid-file-path error, while
the same command succeeds through the independent CLI control. Its proof stays
absent. The module returns Safe and refuses two actual attempts on one selection,
with no original exploit body or settings mutation. This qualifies the observed
1.5.5 control, not every higher version.

## Retained setup and harness diagnoses

The first image-metadata probe assumes an optional `Config.Cmd` field exists.
The image uses an entrypoint and omits Cmd, so inspection stops after a successful
pull. No container or module is invoked. Optional map indexing corrects the probe.

The first application setup starts normally, but Compose expands Perl variables
inside an inline health command. Captured health syntax errors identify that
probe failure; a read-only script avoids interpolation. The original setup,
input bytes, application logs and successful exact teardown are retained.

The first fixed native control correctly rejects injection, then unnecessarily
resubmits unchanged settings during cleanup. The [publisher's settings service](https://github.com/vexorian/dizquetv/blob/196033844ac9abfa32819653d221b3fff2696677/src/services/ffmpeg-settings-service.js)
hides the lock timestamp from the API and extends it on an accepted update. The
disk comparison exposes the changed timestamp. Fixed controls now avoid
successful writes and redundant restoration. The timestamp remains in the full
comparison; primary errors and cleanup errors are retained separately. These
three failures precede all module invocation. Final native controls and both
first maintained functional frames pass. No production fault is claimed.

## Currentness, resources and scope

The latest retained set reaches **103 cases / 30 profiles**, retaining **43
used/closed OS sessions**; no new sessions are counted here. All **309 declared
input fingerprints** reconcile, and **208 current resource-event captures** are
zero. Historical coverage is **326 owners in stated paths, 700 profiles and
4,878 functional cases**. Registration and these path counts do not establish
complete module coverage. The complete inventory remains in scope.

Only one capped application container runs at a time: 384 MiB, 0.7 CPU, equal
memory/swap limits and 96 PIDs. All **16 new / 576 recorded Docker objects**
independently verify absent, including failed setup phases and stopped image-tool
probes. Both local contexts finish globally empty, with owned ephemeral networks
and volumes absent. No agent or Docker-backed connector is initialized here.

Four new Ruby files pass RuboCop with zero offenses; module-document tidy,
Python/Perl parsing and actual Compose startup pass. The existing human-written
Scenarios section remains byte-for-byte unchanged. No full unit suite is run.
These Docker tests remain opt-in; published-head CI is separate.

Reverse sessions, default fetch delivery, Windows and other releases remain
unqualified. The current Linux Docker fixture cannot establish Windows batch
execution. Stock curl/wget absence is a prerequisite gap for fetch delivery.

## Self-review

| Area | Assessment |
| --- | --- |
| Summary | Adds one owner in two native-gated publisher-image profiles. |
| What looks good | Exact native counterparts, real stdout/UID proof, COMMAND precedence, complete storage recovery and strict fixed-release refusal. |
| Concerns | Session, Windows and other release paths remain unqualified; non-session cleanup acknowledgment is explicit. |
| Suggestions | Qualify available reverse-session delivery next, then continue the full inventory queue. |
