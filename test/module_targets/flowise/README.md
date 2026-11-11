# Flowise model-free container targets

These profiles use unchanged Framework owners with official digest-pinned
Flowise and ordinary SQLite/account/MCP APIs. Registration alone does not
establish qualification; see the [campaign checkpoint](../CAMPAIGN.md) and its
linked evidence for verified scopes. Setup/native failure is not a module
verdict. Run from the repository root:

```sh
nice -n 10 bundle exec ruby tools/dev/run_guarded_module_target_tests.rb flowise_300 flowise_basic flowise_305 flowise_306 flowise_311 flowise_312
```

The guard holds one cross-worktree lock, refuses existing containers and plans
above five, and includes its source in input maps. One project runs at a time.
Normal metadata validation/reuse and 120-second readiness/prompt and 600-second
family bounds apply. Recorded native CLI calls retain40-second bounds; HTTP
uses10seconds and actual Exim delivery observation10seconds. The standalone
first native gate has its own180-second probe bound, separate from readiness
and the canonical1800-second build ceiling. Only Apache publishes a random loopback port; app and
Framework use an internal network. No external callback, host socket, privileged
container or new project dependency is needed. The npx path uses only an internal
HTTP tar URL, with the npm registry deliberately pointed at genuine local Apache
404 responses; native execution must prove this configuration works.

| Profile | Cases | Release/mode | Services | Declared MiB/CPU |
| --- | ---: | --- | ---: | --- |
| flowise_300 |3|3.0.0 open|3|1888/2|
| flowise_basic |1|3.0.0 real Basic environment|3|1888/2|
| flowise_305 |3|3.0.5 JWT and actual SMTP|4|1984/2.1|
| flowise_306 |2|3.0.6 fixed JS/reset|4|1984/2.1|
| flowise_311 |2|3.1.1 npx with reporting DB|4|2144/2.15|
| flowise_312 |1|3.1.2 npx fixed with DB|4|2144/2.15|

Base limits: Flowise1024MiB/0.9CPU, Framework768MiB/1CPU, Apache96MiB/0.1CPU.
SMTP adds the existing genuine Exim96MiB/0.1CPU, with unchanged configuration
from the mail-capture fixture. DB adds the existing pinned PostgreSQL256MiB/0.15CPU.
These declared limits need actual config/cgroup/health/no-OOM/native verification;
this guide does not claim they fit before that gate. Flowise requests a512MiB
Node heap. The native tool records a separate configured Node heap and actual
process/environment facts; a CLI heap reading is not a live application heap dump.
Five releases have about4.50GB unique compressed layers; pull/disk cost is
separate from running caps. Image details and hashes are in profiles.json.

## Authentic prerequisites and controls

Native controls require installed package versions and exact relevant publisher
compiled-source hashes from published_artifacts.json, plus HTTP version, Node/
npm/npx identity, real SQLite persistence, actual resources and healthy processes.
The vendor Dockerfile uses an unpinned global npm install; a digest/tag alone does
not establish installed version. Publisher-distributed package/JS bytes are
source-only HTTP receipts, not executed substitutes for the target application.
A mismatch stops setup for investigation.
Package identity follows the actual Flowise dependency lookup and public entry
point before reading its real manifest. This supports packages whose exports
hide `package.json`; package names, versions, entrypoint containment and every
original publisher hash remain required. Resolving an entry point does not load
or execute that package.

The native MCP program uses the target's genuine installed MCP SDK and must
return its actual tool identity/PID and live self /proc snapshot through Flowise.
The tagged toolkit closes its initial client before returning; natural PID
absence is verified afterward, rather than requiring a lingering process. Independent handcrafted API requests must execute
harmless exact target bytes on affected releases and fail on fixed releases.
HTTP status/listActions output alone is insufficient. All native command/file
bytes and peer responses are retained. API helpers keep fresh login cookie jars.

Modern accounts are registered using the real account API. Fixture email is
module_target@module-target.test and initial password FlowiseNative!42. Legacy
Basic uses module_native/module-target-basic-password. Exim is local-only and
uses its existing capture_user authentication and real spooled MIME. The native
gate authenticates/sends a normal message before the account-reset controls.
Password recovery must consume a token from actual delivered email, not pretend
that SMTP succeeded. Account restoration proves the original secret works and
consumed tokens refuse reuse; timestamps/salted hashes/logs may legitimately
change and remain until disposable target teardown.
The pinned 3.0.5/3.0.6 reset handlers mask an invalid-token exception with a
transaction-not-started HTTP500. The replay control requires that exact captured
error, a distinct replay password, independent read-only SQLite user/token row
snapshots immediately before/after replay, a fresh current-password login and
replay-password refusal. The 500 alone cannot satisfy the control. Snapshotting
before the login probes separates replay effects from authentication metadata.
The same proof protects native recovery and the affected owner's consumed token;
existing exact loot, changed/original login checks and restoration remain required.

The 3.0.5/3.0.6 app profiles explicitly set `ALLOW_UNAUTHORIZED_CERTS=true` for
**unverified local SMTP TLS**. The pinned compiled mailer treats any nonempty
value, including `false`, as disabling peer verification; the native identity
gate requires the literal `true` in resolved Compose and the app environment,
checks the exact installed mailer bytes, records resolved Nodemailer identity
and refuses a global `NODE_TLS_REJECT_UNAUTHORIZED` override. Actual STARTTLS,
SMTP authentication, delivered MIME/token, reset, fresh login, consumed-token
refusal and existing old/new-password assertions remain required. The preserved
strict 3.0.5 diagnostic rejected the disposable Exim peer with `CERT_HAS_EXPIRED`;
its certificate reported a 1970 expiry. This configuration makes no claim that
SMTP certificates are trusted or verified. Shared Exim configuration stays
unchanged, and other profiles do not enable this app setting.

MCP profiles connect/migrate a real Framework DB and query it independently with
psql. Exact service identity/workspace is required; a console Boolean is not
reporting evidence. ATO's current owner stores loot, not a validated credential
login graph: those profiles claim only exact loot and real authentication, with
no DB reporting qualification. Adding DB to an ATO profile would resolve to five
services/2240MiB/2.25CPU and needs independent preflight/native evidence.

## Exact initial cases

Every numbered case repeats twice, including meaningful refusal/state checks.

1. Open customMCP check and quiet exact zero-byte command proof.
2. Open JS check and a genuinely used fetch session with PID/file cleanup.
3. Both owners on unrelated Apache and real missing paths, without false proof.
4. Both legacy owners with valid real Basic and rejected wrong/missing credentials.
5. JWT JS session/command and rejected wrong/missing account credentials.
6. Account takeover with exact loot, new/old login comparison and ordinary recovery.
7. Nonexistent account, without false credential loot.
8. Fixed JS check/default block and real explicit override refusal; legacy direct
   command's unauthenticated JWT refusal is an authentication-policy observation.
9. Fixed reset check/default block and no-token override, with old login/recovery.
10. npx archive fetch and used Python command-shell session, plus genuine service reporting.
11. Missing/wrong npx JWT without archive delivery, marker or false access claim.
12. Fixed npx check/default block and explicit --yes refusal, plus service reporting.

The passive recorder installs only the selected owner classes and calibrates the
real target/payload catalog and writable empty file. It delegates once and records
COMMAND-ARG, RETURNED-TAR, REQUEST-ARGS/RESPONSE-BODY, HTTP-REQUEST and RESPONSE-ARGS.
These are API argument/return/peer observations, **not socket captures or PCAP**.
The actual archive is decoded after production, not regenerated. Tar return and
served-body bytes must match, with a genuine target peer and independent session
proof. API errors/returns and actual payload serialization remain unchanged.

Before owner recording/examples, the 3.0.0 and 3.0.5 session profiles separately
calibrate the actual WGET/Linux x64 Meterpreter family through ordinary
multi/handler and a native launch in the real app. They use ports 4455/8095,
separate from owner ports 4444/8081. The known
executing handler's cached EncodedPayload bytes are read once, copied unchanged
with verified native owner/mode/SHA, then executed as the measured application UID.
Real opened/used session, file API write/removal, target UID/PID/ELF/SHA, graceful
PID/fetch-file absence, host cleanup, stopped owned job and an actual 404 response
or closed port are mandatory. Calibration execution has a local 120-second bound;
its CLI calls reuse the existing 40-second process-group executor. Ensure cleanup
runs separately, including after a failed gate. This is independent of the SDK
process and makes no owning-module success claim.
The positive `flowise_311` profile separately calibrates the actual reverse-Python
command shell at4456 using the same cached-command, app-UID installation and
bounded native launch. Exact session-created file bytes/SHA/UID and live PID/
ancestry must be observed; remote exit and target PID absence precede explicit
host shell closure, owned job/listener cleanup and state restoration. `flowise_312`
has no owning positive session and does not run that calibration. These are
mandatory runtime gates, not claims that a registered profile already passed.

Both native and owner fetch options use bare URI leaves. The fetch component
adds the leading slash to emitted URLs; exact resource checks use `/leaf`.
The native calibration records copied host ownership, then prepares only its
fresh script for the measured numeric application UID/GID and mode0600. Exact
SHA checks before and after preparation must match the cached command bytes.

Sessions must open AND be used, create exact fresh target bytes as the native UID,
then gracefully exit. Newly observed payload ancestry PIDs must become absent;
callback listeners must close. Generated fetch files must actually disappear
within the local bounded gate. Jobs are stopped explicitly. Owned HTTP resources
must be empty, followed by actual404 responses or observed closed-port refusal;
pooled listener lifetime is recorded separately. Scoped target/npm files, links
and directories are captured then restored using only exact new owned names.
This is fixture restoration, not a claim of automatic owner cleanup.
After a command shell's target ancestry is proved absent, the fixture explicitly
closes that finished host session through `shell_close` and still requires an
empty host registry. This is operator stream/session cleanup, separate from the
already observed remote exit. Meterpreter retains its existing exit path. The
session proof records which host cleanup path was used.

## Boundaries and pending paths

[Direct-command advisory](https://research.jfrog.com/vulnerabilities/flowise-os-command-remote-code-execution-jfsa-2025-001380578/)
and tagged source distinguish optional Basic in3.0.0 from JWT in3.0.1. Exact3.0.1
runtime coverage remains pending; authentication hardening does not prove all
authenticated commands are removed. [JS fix](https://github.com/FlowiseAI/Flowise/security/advisories/GHSA-3gcm-f6qx-ff7p)
replaces Function evaluation with JSON5 in3.0.6; earlier source-supported paths
still require native proof. [Reset fix](https://github.com/FlowiseAI/Flowise/security/advisories/GHSA-wgpv-6j63-x5ph)
sanitizes the response in3.0.6. [npx fix](https://github.com/FlowiseAI/Flowise/security/advisories/GHSA-m99r-2hxc-cp3q)
blocks --yes in3.1.2; CUSTOM_MCP_SECURITY_CHECK stays enabled and stdio permitted.

Windows, application HTTPS, other roles/branches, concurrency and other payloads remain pending.
The separate CSV-agent/Ollama owner is not selected: it needs genuine model
inference at its unchanged temperature0.9, pinned Pyodide packages/cache, proof
of actual Python-to-host execution, and its own measured resource/timing gate.
A real small model exists; it is not excluded merely for size, and no model or
Flowise response may be simulated. Existing human Scenarios remain unchanged.
