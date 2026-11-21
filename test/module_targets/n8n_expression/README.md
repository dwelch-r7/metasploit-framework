# n8n authenticated workflow expressions

```sh
MODULE_TARGET_NAMESPACE=n8n-local bundle exec ruby tools/dev/run_guarded_module_target_tests.rb n8n_expression n8n_expression_fixed
```

Run serially. These profiles reuse the existing official n8n target definition
with only its application service: pinned Linux amd64 1.120.0 or 1.120.4, Node
22.21.0 and UID 1000. Each stack has one capped container, 1 CPU, 1536 MiB
memory/equal swap and 192 PIDs, with its port published on loopback. No application
code is patched. `vendor.json` records the observed application, workflow and
core package versions plus authentication/controller/expression/execution hashes.

Native controls perform real first-owner setup and password login. An ordinary
IIFE computes a string through a Manual Trigger/Set workflow. A separate harmless
expression uses the installed sandbox escape to write exact proof bytes through
Node's file API. The vulnerable release must create a UID-1000 file; the fixed
release must retain normal IIFE evaluation while rejecting `mainModule` access
without writing that file. Terminal execution data is decoded using the image's
installed `flatted` package. HTTP 200 alone proves neither execution nor safety.
These releases follow the [advisory database](https://github.com/advisories/GHSA-v98v-ff95-f3cp)
and [tagged fixed sandbox source](https://github.com/n8n-io/n8n/blob/n8n%401.120.4/packages/workflow/src/expression-sandboxing.ts).

After calibration the real module must return reason-bearing Appears/Safe checks.
The vulnerable profile also checks an incorrect password and a natively refused
connection, then executes two `cmd/unix/generic` commands on one selection with
AutoCheck disabled. The payload excludes apostrophes: proof data is encoded
inside an allowed command rather than claiming the transport accepts forbidden
bytes. Target files must contain the exact quote/backslash/Unicode/CRLF proof as
UID 1000. The patched profile repeats AutoCheck refusal without workflow delivery.

Two complete unrelated workflow records must survive every public operation.
Native API checks and read-only SQLite probes require the same full global
workflow-ID registry. The module must archive/delete only its own workflows;
fixture cleanup then removes the preserved controls and requires all workflow
and execution rows to be zero. Installed source hashes must still match.
Each native helper retains its original requests, responses and commands.

The default login limiter remains enabled. The vulnerable profile uses five
real login attempts: native login, real check, bad password and two command runs.
Command runs omit the redundant AutoCheck login after the dedicated check case.
Native fixtures reuse genuine cookies; no authentication token is forged.

Default fetch/Meterpreter delivery, Windows, other releases, member roles, MFA,
queue/external-database modes and proxy prefixes remain outside these profiles.
Automated evidence does not replace human module Scenarios. The guarded runner
names/labels projects and removes finished/failed stacks immediately; follow
[CAMPAIGN.md](../CAMPAIGN.md) and verify exact resource IDs are absent.
