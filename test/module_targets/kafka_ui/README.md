# Kafka UI module targets

Verified on 2026-11-19: all three maintained profiles pass **29/0** cases.
The cases comprise **21 Kafka owner cases** and **8 independent real handler
controls**, with **12 owner sessions and 8 control sessions used and closed**.
See [the verification record](../VERIFICATION-20261119-kafka-ui.md).

These profiles exercise `exploit/linux/http/kafka_ui_unauth_rce_cve_2023_52251`
against unmodified Kafka UI releases and a genuine Kafka broker. The shared
[service definitions](services.yaml) pin images and cap CPU, memory and PIDs.
Framework runs on the host; session profiles add the existing reporting database.

| Profile | Kafka UI configuration | Services | Expected cases |
| --- | --- | ---: | ---: |
| `kafka_ui_071` | 0.7.1 default Groovy filtering | 3 | 13 |
| `kafka_ui_072_groovy` | 0.7.2, `FILTERING_GROOVY_ENABLED=true` | 3 | 13 |
| `kafka_ui_072_default` | 0.7.2 default filtering disabled | 2 | 3 |

Version 0.7.2 keeps the unsandboxed Groovy engine behind an optional setting.
Its default and enabled configurations return identical version metadata. The
module therefore reports `Detected`; AutoCheck warns and permits the attempt.
The disabled profile must produce a feature-specific rejection, an operator
failure and unchanged native state. HTTP 400 alone does not establish mitigation.

## Run

Use a working Framework bundle, Docker Compose, Python 3 and NASM on the host.
The assembly probe reuses [the existing source](../druid_sessions/native_exit.asm).
The tested UI images provide `sh`, `nc`, `wget`, `base64` and `unzip`; Bash, curl
and Python are absent. Session cases use netcat and WGET fetch payloads.

From the Framework repository root:

```sh
export MODULE_TARGET_NAMESPACE="kafka-ui-$$"
bundle exec ruby tools/dev/run_guarded_module_target_tests.rb \
  kafka_ui_071 kafka_ui_072_groovy kafka_ui_072_default
```

The launcher shares one heavy-work lock, assigns explicit namespaced Compose
projects and removes each completed stack before starting the next. The positive
profiles use at most three services: UI at 0.75 CPU/1 GiB/128 PIDs, Kafka at
0.75 CPU/768 MiB/128 PIDs and reporting DB at 0.25 CPU/384 MiB/128 PIDs. The
default-disabled profile omits the database. Published ports bind to loopback.

Artifacts are written under `tmp/module-target-tests/`. Retain failure evidence,
check the exact project/resource IDs in its receipts, and verify that created
containers, ephemeral volumes and networks are absent after teardown. Cleanup
must preserve resources owned by other work.

## Coverage and independent controls

Native controls verify application identity, JAR hash, UID100, real broker bytes,
UI filtering, two create/produce/read/delete cycles, Groovy execution or its
explicit disabled-setting rejection, and resource-event counters. Every command
is submitted as the exact same bytes to an independent native control. Its proof
path must be absent before the owner runs. The owner must produce exact file bytes,
preserve operator input, restore topics/messages and permit a repeated run.
Quoted/backslash/dollar input, Unicode and emoji, physical newline/tab bytes,
shell variables and command substitution are covered. Actual socket write buffers
are captured passively and checked against their decoded Groovy query.

Each positive profile has three command cases and ten session cases. Four session
cases independently launch real Framework handlers outside Kafka before any
corresponding owner verdict. Six owner cases use netcat, x86/x64 inline fetch and
staged x64 Meterpreter, with netcat/x64-fetch repeats on the same selected module.
Native prerequisite cases and owner cases must be reported separately.

Session controls read the already cached payload and actual registered fetch
binaries. They require ready events, public remote session API use, UID100
file/process evidence, a live TCP connection and actual database owner, payload
and workspace records. They then require remote exit, process/connection/FIFO/
fetch/proof cleanup, no Framework jobs or sessions, and database `closed_at`.
A failed prerequisite withholds its dependent owner path; a failed test remains
unclassified until the target and harness have been investigated.

The component reuses the existing Rsync console/native helpers and Druid session
controls. It installs no runtime inside the stock UI image. The native source
versions and image references are recorded in [releases.json](releases.json).

## Limits

Other releases, authentication
configurations, architectures, transports, concurrent target changes and payloads
requiring unavailable stock commands are unqualified. The existing inherited
default-payload lint offense is separate from functional results. Human-written
module Scenarios remain unchanged.
