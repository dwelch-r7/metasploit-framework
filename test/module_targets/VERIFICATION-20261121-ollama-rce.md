# Ollama native-gated traversal and actual commands

Two new profiles pass **7 examples / 0 failures / 0 pending**. Independent
native controls establish the loader, ordinary OCI model registration, physical
traversal success/denial and genuine API runner execution before the actual
module is assessed. Two real `linux/x64/exec` commands pass on one selected
module; repeated fixed-release AutoCheck refusal passes. **Default Meterpreter
sessions and automatic library cleanup remain unqualified.** Production source
is unchanged. No PR is created; the broader inventory goal remains active.

The previous sixteen stated profiles retain 53 cases and twenty-two used/closed
sessions with all 188 declared inputs unchanged. The latest eighteen profiles
have **60 qualified cases**, 204 current declared inputs and 100 zero cgroup
event captures. Historical coverage reaches **323 owners in stated runtime
paths, 688 profiles and 4,835 functional cases**. These are covered paths, not
fully qualified modules or proof that the complete inventory has been tested.

## Native target qualification

Recipes build from official pinned Linux amd64 Ollama 0.1.33 and 0.1.34 images,
Ubuntu 22.04.4, running as UID zero. A resident Python observer starts the vendor
`/bin/ollama serve`. Original Ollama, libc and dynamic-loader hashes must survive
the observer installation and match again after owner execution. Image digests
and fingerprints are retained in [vendor.json](ollama_rce/vendor.json).
The independent benign constructor is built from the supplied C with GCC;
the module still generates its own library through Metasm.

Both images must pass ordinary `LD_PRELOAD` loading through `/usr/bin/true` and
normal OCI pull/show of a minimal GGUF model. The model contains architecture
metadata and no weights; this tests registration and runner startup, not useful
inference. Native traversal on 0.1.33 writes exact quote, backslash, Unicode and
CRLF bytes. The independent library/preload chain then records execution inside
the actual `ollama_llama_server` CPU runner, with the existing Ollama server as
parent and UID zero. Its proof is absent immediately before chat. A chat timeout
is retained separately and is not the success oracle.

On 0.1.34, local loader and ordinary registry controls still pass, while the
malformed digest is rejected and the traversal file remains absent. This agrees
with the [vendor advisory](https://github.com/advisories/GHSA-8hqg-whrw-pv92) and
[original research](https://www.wiz.io/blog/probllama-ollama-vulnerability-cve-2024-37032).

All armed-state observation uses the already-running observer's file APIs over
host HTTP. **No Docker healthcheck or target helper exec runs while the global
preload is armed.** Such a helper could itself execute the constructor and
invalidate the claimed API proof. The observer's two ports publish on loopback;
its unauthenticated file API is a disposable lab fixture, restricted to task
paths, the proof and preload.

## Maintained owner tests

| Profile | Examples / failures / pending | Functional seconds | Qualified behavior |
| --- | --- | --- | --- |
| [ollama_rce](ollama_rce/README.md) | 4/0/0 | 82.72 | Native controls, actual Appears, two command executions on one selection |
| [ollama_rce_fixed](ollama_rce_fixed/README.md) | 3/0/0 | 16.34 | Native positive/denial controls, actual Safe, repeated AutoCheck refusal |

Passive traces retain original source paths, check reasons, requests/responses,
generated ELF bytes and physical preload before the module's own chat trigger.
Each physical library equals the actual generator return. Each command writes
its expected exact bytes as UID zero. The module's model aliases disappear;
Framework sessions and jobs remain empty. The fixed attempts issue only the
version GET and never enter the exploit body or generate/deliver a library.

Command cases explicitly set `AllowNoCleanup=true` because there is no session
to provide FileDropper's file API. Each remaining library is recorded before
resident fixture recovery. Exact task files and preload are absent afterward;
this does not establish automatic module artifact cleanup. Other payload
families, default sessions, other releases, nonroot deployments and alternate
model directories remain outside these profiles.

## Failures retained and lifecycle

The initial build invocation fails before startup because the selected Docker
context differs from the default builder's context. Explicit matching context
and builder settings resolve that setup error. Two native attempts then expose
an incomplete readiness exception list and an incorrect Python request-method
accessor. Neither invokes the module. Corrected vulnerable and fixed pilots pass.

The first maintained frame has **4/2/0** and **3/1/0**: native controls and real
checks pass, but command cases encounter lost cross-example harness state before
invocation. The handler-disabled fixed attempt is rejected by FileDropper's
preflight before AutoCheck. Shared receipt state and explicit `AllowNoCleanup`
correct those harness issues; the final full replay above passes. Original
receipts, frozen inputs and failed output are retained separately. No production
fault is inferred from these failures.

All phases run serially with **one capped container**: 1 CPU, 1024 MiB
memory/equal swap, 128 PIDs. Unique projects and namespace labels identify
resources; native registries close in `finally` and finished/failed stacks are
removed immediately. All **18 new and 467 recorded Docker objects** are
independently absent. The final global inventory contains **zero containers,
including stopped ones**; no owned ephemeral network or volume remains. No
images/build caches are pruned and no daemon is restarted.

Three new Ruby files pass RuboCop; Python parsing, both Compose configurations,
documentation tidy, excluded acceptance discovery and diff whitespace checks
pass. The original **1,588-byte human Scenarios tail** is unchanged, SHA256
`c225508d4c4b4a1721a8c1c4293719098b46efdb5dbb8b018717567f79f6844d`.
Automated captures do not supply human Scenarios.

Self-review summary: qualification is limited to the stated checks and commands.
What looks good: independent controls, physical evidence, unchanged vendor files
and verified serial cleanup. Concerns: default sessions and automatic cleanup
are still unqualified. Suggested next step: independently calibrate the normal
Meterpreter path before assessing those owner behaviors.

## Evidence

Immutable capsules under `/Users/dwelch/.codex/reports/` retain source inputs,
commands, HTTP journals, physical proofs, traces, resource events and exact-ID
cleanup receipts. `SHA256SUMS` seals each capsule. Native pilot capsules are
`ollama-native-0.1.33-20261121t082126` and
`ollama-native-0.1.34-20261121t082159`; the failed maintained frame is
`ollama-rce-harness-state-failure-20261121T082452`. The final maintained frame is
`ollama-rce-maintained-20261121T082705`. The private audit/qualification pointers
are in `tmp/ollama-rce-feasibility/`; local temporary paths are not repository
dependencies.
