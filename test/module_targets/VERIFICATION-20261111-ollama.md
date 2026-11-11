# Ollama enumeration verification — 11 November 2026

The checkpoint is **196 qualified modules, 140 profiles and 1,547 passing
functional examples**. The new `ollama` profile qualifies
`auxiliary/scanner/http/ollama_info` and fixes two genuine reporting errors:
unavailable detail responses abort enumeration, and multiline system prompts
are truncated. The broad module campaign remains incomplete.

## Genuine application and resource budget

The normal vendor Ollama **0.1.48** server and CLI import a real SmolLM-135M GGUF.
The CLI creates two local model aliases with ordinary Modelfiles: one has a
configured temperature/system prompt; the other omits them. Native inference
produces a real token, with one CPU inference thread, a 128-token context and no
GPU allocation. Model listings, running state and detail responses are generated
by Ollama; no application protocol handler or API response is replaced.

The Linux amd64 base manifest is pinned to
`sha256:c9bfaf0363f600acf1f7953152dfd56100d6a22cfbddb2f406dea999591f3117`.
Its exact registry config digest is
`sha256:b9ff40c765dae0421f9333e858bdadc06b434ccbdf32538b603f996ca882efd6`.
Root verifies the actual runtime filesystem starts with all vendor config
`rootfs.diff_ids`; the base is held in BuildKit content rather than registered as
a separate local image. The observed runtime image is
`sha256:5977305369c1ccbf7e2ce5aa7f7c03d7870c05ffee43855588989624aa630630`.
Python packages resolve from Ubuntu archives during the build; future package
resolution is not claimed byte-identical.

The vendor-distributed GGUF is **91,727,296 bytes**, SHA256
`eb2c714d40d4b35ba4b8ee98475a06d51d8080a17d2d2a75a23665985c739b94`.
Readable download/import commands verify that digest. Model weights are not
checked into the repository. The [versioned vendor API](https://github.com/ollama/ollama/blob/v0.1.48/docs/api.md)
and [Modelfile documentation](https://github.com/ollama/ollama/blob/v0.1.48/docs/modelfile.md)
describe the native operations used.

Three containers total **1,856 MiB/1.6 CPUs**: Ollama 1,024 MiB/half a CPU,
Apache 64 MiB/one-tenth CPU, and Framework 768 MiB/one CPU. Swap equals each
memory limit; PID limits are 128/64/256. Apache uses one eight-thread worker.
Actual live inspection confirms these limits, disabled privileged mode and no
GPU device request. Host bindings are random loopback ports; Framework uses the
internal network. No Docker volume or model state survives teardown.

The target cgroup peak reaches its **1 GiB cap before owning calls**, including
startup/native activity and filesystem cache. All thirteen final native snapshots
retain memory `max=15`, `oom=0`, `oom_kill=0` and PID `max=0`. This is not a claim
that observed memory stayed below the cap, or that the peak isolates a particular
setup operation. No new memory-limit events appear between those snapshots.

## Complete native and owning results

Run **20261111T123128-5bae53**, source
`6b94625996d80a835ca37db7d32cac7985ff11b7`, passes **12 examples with zero
failures, pending or errors outside examples** in **79.318974 RSpec seconds**.
The actual manager and independent live observer exit zero.

Twenty-four owning calls exercise every case twice:

- Running plus installed models, installed-only state and an empty catalog.
- Exact names/tags, status, binary size display, parameter size, temperature and
  present/absent system prompts, without duplicate running rows.
- A genuine two-line system prompt, retaining both lines without Modelfile quotes.
- Ordinary Apache Basic authentication for all routes or only model details,
  with accepted credentials and unauthenticated refusals.
- A reverse-proxy URL prefix, unrelated Apache content, a missing base path and
  a closed port, with no invented model tables.

Every native preparation and before/after phase passes. The thirteen native
records contain six bounded one-token inference proofs; startup has its own
import/inference health gate. Native clients independently verify CLI/API version,
actual model details, authentication refusals and successful authenticated access.
Installed-only, empty and multiline states are restored to the two-model/running
baseline after their cases. Stable before/after model names, sizes, digests and
details match; modification/expiry timestamps are not treated as stable identity.

Call-through instrumentation retains **84 HttpClient observations**: 74 final
HTTP 200 responses, six 401 responses, two 404 responses and two nil responses
for refused connections. Authentication challenge/retry transactions inside the
client are not separately counted. These are actual returned HTTP bodies and
console output, not a packet capture or SQL persistence test.

Root verifies all **43 current selected input hashes**, each separate owning
record, native identities, restored state and both fixes. The first real console
prompt, isolated BOOT and two fresh metadata snapshots are observed, with no
first seed. Nine independent cleanup queries prove the three exact containers,
two networks and project-label inventories absent; global containers are empty.

The immutable **166-file** source/run/review package has manifest SHA256
`f212b09651d41cc209185e85770bb904aeb684303d34c18376dfc3eee08426b7`.

## Confirmed module errors

A genuine Apache policy permits model discovery while requiring authentication
for `/api/show`. Native requests without credentials receive 401; valid
credentials retrieve the correct backend details. The original module's nil
`details.dig` aborts enumeration. The fix preserves discovered running/installed
rows and marks unavailable parameter size `N/A`, matching the other missing fields.
The identical ten focused cases have eight failures before and zero after;
both valid-data controls pass before/after. Original commit
`ca35967debf7021e4460f374e568566ef1bd7f6c` is imported as `feb4455f51f`.
Its independently verified 38-file package has manifest SHA256
`9d2e131ba033c644decce45688b5f2c9fedb861ba4899a0750477c20d54c1712`.

After the native controller is corrected, the next full run passes eleven cases
and exposes one remaining module error: parsing the first Modelfile `SYSTEM`
line loses the genuine structured prompt's continuation and retains quoting.
The fix prefers a present structured `system` value; explicit empty/null is
`N/A`, and absent fields retain the existing legacy fallback. Twelve identical
prompt cases have six failures before and zero after; the earlier ten tests
remain unchanged and pass. Original commit
`4026d54a961f1a66d14173829196d8ed31482145` is imported as `8ec13572ce8`.
The independently verified 180-file package has manifest SHA256
`02fc54f10e591b1d298782389b945d9accb6332e22ef6d0234e8ae9185d2d05a`.
Root's final normal spec invocation passes 29 examples: 22 module regressions
and seven shared formatter checks. Both fixes then pass the complete live profile.

## Preserved setup and failing owning runs

| Run | Actual result | Immutable manifest SHA256 |
| --- | --- | --- |
| `120605-8357e5` | Minimal Python lacks a required standard-library module; build stops before containers | `1b6880b84fae194363003832258dfd4afcbad150a8cb6d606bbd1a62cb12da13` |
| `120742-f774ac` | Readiness socket timeout during vendor runner extraction; zero owning calls | `dd1517a4cd12d33375a10be1684215d6de7c197939aa1548a9df3fdfbd1b2ba4` |
| `121000-52a0be` | Default Apache workers exceed PID cap; zero owning calls | `42324cfd6f2c955b279a68265a3314fc745fba6be6bc6993e16ef6b4e8703d15` |
| `121139-b5ad03` | Eight cases pass; one genuine nil-detail crash and three native state-preparation timeouts | `d02366c09184edde7542ac759a72989d093b8e910f6615cfe1279a56a60ffe61` |
| `122036-6fa05a` | All native transitions pass; eleven owning cases pass and multiline prompt output fails | `95256cb6617554e85ed7349241d31942daf2b1015212eb30bfbf32456001f78a` |

The native unload request originally omitted the bounded context/batch/thread
options, causing a larger default-runner reload and timeout. Reusing the actual
successful inference settings makes all state changes pass. The earlier memory
peak snapshot alone does not establish which operation reached the cap. An
unsupported harness `ConnectTimeout` option is removed; the registered HTTP
timeout remains configured. Native failures are kept separate from module
failures, and all original twelve cases are retained.

Each actual manager terminal and exact cleanup is verified before the next
runtime. The Apache failure's exact IDs come from the manager's saved inspection;
no independent live observer was started for that attempt. The later runs have
independent live/cold observations. A contemplated early interruption was not
sent: the affected run had already terminated and cleaned up naturally.

## Remaining scope and checks

Changed helpers/specs pass RuboCop and syntax; Python sources parse and shell
sources pass syntax. The module retains its one existing duplicate-`RPORT`
warning, independently compared with the base; actual msftidy exits two for that
same finding. Documentation lint passes, and human Scenarios remain byte-identical.

Registration covers 198 sources, with sixteen individual reviews and zero stale
reviews. The queue still has 307 documented container hints pending review,
within 4,622 module candidates. Other Ollama releases, GPU inference, large
catalogs, incorrect passwords and additional model-name/metadata formats remain
unqualified. No full
Framework suite or PR is created. Three other registered lab profiles and the
historical Java DGC prerequisite remain separately unqualified.
