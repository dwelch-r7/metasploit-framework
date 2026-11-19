# Native Kong Gateway command and session qualification

Verified 2026-11-19 against source SHA-256
`7b0d49e8f38f20c1159b2525397da8c0f09147b8656eb2b00161b94e9aa77e54`.
The [fixture guide](kong_gateway/README.md) and
[functional spec](../../spec/modules/exploits/multi/http/kong_gateway_admin_api_rce_target_spec.rb)
provide the reproducible setup. No PR is created; the broader goal remains active.

| Profile | Raw cases | Kong owner cases | Independent handler cases | Owner sessions used/closed |
| --- | ---: | ---: | ---: | ---: |
| `kong_gateway_214` | 13/0 | 11/0 | 2/0 | 3 |
| `kong_gateway_no_plugin` | 3/0 | 3/0 | 0 | 0 |
| Total | 16/0 | 14/0 | 2/0 | 3 |

Two additional genuine handler sessions are used and closed. The sixteen new
historical cases include those explicit prerequisites. This adds one owner and
two qualified profiles, reaching **311 runtime owners in covered paths,
643 qualified profiles and 4,654 historical functional cases**.

## Genuine target and independent controls

The host uses macOS, Ruby 3.3.13, its existing bundle and Python standard library.
The stock Kong process and remote file/session proofs run as UID 100. No package
is installed in the application image. Images are pinned in the shared services:

| Role | Image |
| --- | --- |
| Kong 2.1.4 | `kong:2.1.4@sha256:0ea0ea0e794b215a76cd6f83f1f022d4c10c068fa10575670984b97b24aec01f` |
| Kong PostgreSQL | `postgres:9.6-alpine@sha256:8342bcb43446694428ec6594e72e4299692854f0fc3aca090b0ab46f4c7f32a1` |
| Framework reporting | `postgres:16@sha256:933463a6c8eba2b9f5cd414138738cd8d5519cd2c471214c222652f547a66a32` |

Native application/CLI/database versions, installed Lua source hashes and actual
administration responses establish identity. Independent route/plugin creation,
execution, deletion and repeat cycles precede owner verdicts. The negative profile
uses the same Kong release with `KONG_PLUGINS=off`; its genuine API rejects the
required plugin. This is a configuration contrast, not a patched release claim.

Seven actual positive owner commands cover plain/repeat execution, quotes,
backslashes, literal dollars, Lua closing delimiters, UTF-8/emoji, physical
newline/tab, CRLF and shell variable/command substitution. Each same-byte command
first succeeds through independent native Lua decimal-byte construction; that
proof file is removed before the owner runs. Passive observations retain actual
owner inputs, socket buffers, form fields, response bodies and exact UID 100 files.
The command input remains unchanged afterward.

Both profiles also check an independently refused administration port. Disabled
plugin discovery returns Safe with a reason, and execution refuses before route,
plugin or file creation. Selected lines from the real check and refused run (prompts omitted):

```text
[*] 127.0.0.1:53472 - The target is not exploitable. The Kong pre-function plugin is not available on the server
[-] Exploit aborted due to failure: not-vulnerable: The Kong pre-function plugin is not available on the server
```

The public compatible-payload catalog is captured. Kong's existing Unix-labelled
target advertises Bash and Netcat but rejects Linux fetch adapters. Maintained
owner sessions therefore cover both supported shell families and a Netcat repeat
on the same selection. Real public session APIs perform remote proof; independent
container PID/UID/file/connection observations and SQL owner/payload/workspace
rows corroborate it. Graceful session closure, closed_at, FIFO/proof/script
removal, empty job/session state and five real host-listener refusals are required.

A separate native SDK diagnostic passes 4/0 using Netcat and x86/x64 inline plus
x64 staged Meterpreter handlers. All four sessions are used/closed with actual
SQL reports. These prerequisite controls add no Kong owner qualification and do
not bypass its payload catalog or change target metadata.

## Repairs and retained failed attempts

The original owner lost double quotes and a literal `$HOME` from native-proven
commands. A literal `]]` also caused real Lua validation HTTP400. Shellwords now
quotes the complete Bash operand, and Lua short-string decimal escapes preserve
bytes and delimiters without base64 payload encoding. CRLF preservation is also
verified on genuine Kong. The [Lua 5.1 lexical rules](https://www.lua.org/manual/5.1/manual.html#2.1)
explain the fixed-width escapes and long-string delimiter behavior.

The owner previously reported Appears for the natively disabled plugin. Discovery
now reads its Boolean availability map; known-disabled configurations return Safe,
while missing/malformed inventories remain indeterminate. Both JSON-consumption
points also handle non-object roots with reason-bearing Unknown results.

The same final 33-case focused suite records 26 original-source failures,
8 prior-candidate failures and zero final failures. A separate private oracle,
using the already installed Lua 5.4.8 with os.execute stubbed, improves from 6/9
to 9/9 exact shell operands. Maintained specs require no Lua installation. These
parser/oracle cases do not add native target qualification.

Fixture failures are retained separately: YAML tmpfs quoting, PostgreSQL temporary
socket readiness, an image-entrypoint operation mistaken for a Kong CLI command,
hyphenated inline console options, retained per-module options and an unreliable
host Ruby Socket.tcp refusal oracle. The latter yielded an unconnected socket;
TCPSocket.new reported ECONNREFUSED. Its failed matrix withheld dependent owner
sessions. The replacement Python connect_ex probe was calibrated against the same
known open/closed listener before the successful matrix. No module fault was
inferred from those setup/probe failures. All associated stacks were removed.

## Verification and lifecycle evidence

```sh
MODULE_TARGET_NAMESPACE="kong-$$" bundle exec ruby tools/dev/run_guarded_module_target_tests.rb kong_gateway_214 kong_gateway_no_plugin
```

The complete matrix passes **16/0**, with **479 native assertions**,
**116 zero resource-event captures**, **76 unchanged declared runtime inputs**
and all **ten recorded owned Docker objects independently absent**. One shared
heavy lock serializes stacks. The positive profile needs three capped services;
the negative needs two. Completed stacks are removed before the next starts.

The immutable local capsule `kong-functional-20261119T184732` retains 408 entries;
its SHA256SUMS digest is
`eaaf031e7a28731552872e50cf2ecb0edc0cbe4c1e1d7d5c769df5340bf12167`.
It includes tested sources, raw native/console/wire/SQL evidence, catalog/probe
calibration, independent parent audit and exact resource-removal receipts.

Four small hooks reuse the existing Kafka session verifier. Its complete
three-profile regression passes **29/0**, with twenty used/closed sessions,
832 native assertions, 152 zero resource captures, 77 unchanged inputs and all
25 owned Docker objects absent. This adds no new campaign counts. The corresponding
547-entry capsule `kong-functional-20261119T181109` has manifest digest
`d08bcb4bedc11e16f151586179a5ff6d54f325f3203133f86ce0dc3283087fc2`.

Focused specs pass 33/0; Ruby lint, module tidy and documentation checks pass.
One inherited ModuleMissingAutocheck informational offense remains. Existing
human Scenarios are byte-identical: 2,277 bytes, SHA-256
`978ae60e83049646308c19c82b3de7f076cd3a3cd6894f949de8925deb190dce`.
The full RSpec suite was not requested or run.

## Summary

One owner now has two maintained profiles proving exact command delivery,
supported sessions, reporting, repeat execution and configuration denial.

## What looks good

Genuine native operations, actual compatible payloads, exact files and wire
records, used/closed sessions and independent cleanup checks support the result.
Confirmed module defects and failed setups/oracles remain separately auditable.

## Concerns

Only Kong 2.1.4 on the covered Linux image/configurations is qualified. Other
releases, macOS, authentication, TLS, prefix/proxy routing, other payload families,
concurrent changes and injected cleanup faults are unqualified. Linux fetch
adapters are outside the current target's public compatible-payload catalog.
The inherited AutoCheck informational offense remains.

## Suggestions

Continue the remaining feasibility queue using the guarded namespaced launcher.
Additional payload/configuration coverage needs genuine prerequisites and actual
owner results before increasing coverage counts.
