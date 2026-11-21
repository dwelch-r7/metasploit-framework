# Node V8 debugger check transport repair

Date: 2026-11-21. Expected connection/read failures now return a reason-bearing
`Unknown` and always attempt disconnect. The real pinned Node profile passes
**6 examples / 0 failures / 0 pending**, with six native/owning TCP/TLS shells
fully used and closed. The original module and harness failures remain preserved
in the [previous report](VERIFICATION-20261121-nodejs-v8.md) and raw evidence.

## Reproduction and source scope

```sh
bundle exec rspec spec/modules/exploits/multi/misc/nodejs_v8_debugger_spec.rb
MODULE_TARGET_NAMESPACE=nodejs-local bundle exec ruby tools/dev/run_guarded_module_target_tests.rb nodejs_v8
```

The [existing recipe](nodejs_v8/README.md) and pinned official Node 7.10.1 image,
UID1000, active timer program, 128 MiB/0.5 CPU caps and independent native gates
remain unchanged. TLS applies to the callback payload; the debugger uses TCP.

Only the production `check` method changes. Connection and read guards identify
the failed operation, return `Unknown` with a reason and retain exception details
through `elog`. Ensure attempts disconnect on success/failure and reports cleanup
errors. An original programming error or user interrupt remains visible if
cleanup also fails. Existing successful `Appears` and no-banner `Unknown` reasons
stay unchanged. The nearby FreeSWITCH TCP check supplies the established pattern.

All production bytes before `check` and from `exploit` onward are identical:
metadata, defaults, targets, payload generation and exploit delivery are preserved.
No AutoCheck behavior is added. The original and repaired module SHA256 values are:

```text
original cc88b32c25cac2a0ef3a3473b7db783916cdd32f8fcf38753ca44951f88e4573
repaired acf8af4e97de97510feb6179be112525267c44d9b438fe80ed5909ac2dcce541
```

## Unit and functional evidence

The corrected identical unit spec has SHA256
`cb4994c25f5cf73ee65635f3717a0214b9a54ae7ec49269a78c8f565728371c9`.
A private two-file fixture tree loads the original module with the same spec
bytes and shared Framework libraries. Serial before/after runs reproduce
**36/17/0** and pass **36/0/0**, with zero outside-example errors, in 0.73/0.76
seconds of RSpec execution. Seven examples come from shared support.

The positive handshake is captured from the real pinned Node service. Expected
transport faults are explicitly synthetic boundaries: refusal, unreachable host,
timeouts, reset, EOF and closed streams. The original TCP socket cleanup remains
real. Regressions cover repeated checks, retained configuration, developer
diagnostics, successful classification, unexpected errors, interrupts and
secondary cleanup failures. Native timeout/reset/disconnect fault injection is
not claimed.

Two early unit issues are excluded from module-failure counts. An initial
assertion called nonexistent `ModuleDataStore#values_at`; explicit option reads
correct it. Parallel RSpec processes then raced on a shared constant-audit log,
causing a zero-example baseline startup failure. The authoritative pair runs
serially. The original attempts remain retained.

| Native frame | Result | Seconds | Observed outcome |
| --- | --- | ---: | --- |
| Repaired source, old assertion | 6/1/0 | 149.04 | All six sessions work; correct Unknown returned, but nested eq matcher fails |
| Repaired source, composable assertion | **6/0/0** | **139.91** | All six sessions repeat; strict refused-port check passes |

The old functional `eq([include(...)])` compared the nested matcher as an
object. Changing it to composable `match([include(...)])` preserves the required
Unknown classification, nonempty reason and single result. A separate six-case
probe uses actual original/repaired captures: the original missing result is
still rejected; the repaired Unknown is accepted. Blank/nil reasons, wrong
classification and duplicate results are rejected. Its initial standalone
top-level include-name collision is separately retained as a probe setup fault.

The final real check reports Unknown with an operation-specific refusal reason,
without the former exception/undetermined outcome. Two positive checks on one
selection still return the original protocol-detection `Appears`. Independent
protocol/version/physical-file and callback gates precede native TCP/TLS shells
and four original owning sessions per frame. Actual payload/message bytes,
post-bootstrap events, UID/file bytes, PID/birth and parent, fresh responses,
two-peer shutdown and active callback removal verify. Main program identity,
foreign file and empty Framework jobs/sessions preserve. The two repair frames
retain twelve fully used/closed sessions, including eight owning calls.

## Checks, cleanup and remaining scope

Only the owner source and the assertion helper refresh existing functional
input hashes; the unit spec adds one separately tracked input. The current set
reaches **138 passing functional cases / 38 profiles / 435 inputs**, with **73
ordinary** retained used/closed sessions and **21 separate candidate-source**
sessions. This qualifies the stated Node paths, not all payloads/platforms.

Changed unit/helper Ruby has no offenses. The module retains ten existing
offenses, down from thirteen after modernizing its touched condition; no new
offenses are introduced. Module tidy exits 0 with its existing no-CVE
informational message. Module-documentation warnings are identical to baseline,
and human-written Scenarios remain byte-identical at 594 bytes.

Four final cgroup captures are zero. Each native phase uses one capped container
and removes it immediately. All **4 new / 763 recorded Docker objects** are
independently absent, both Docker contexts are empty including stopped
containers, and callback ports are closed. Raw native/console captures, unit
attempts, oracle controls, hashes and cleanup receipts are sealed locally through
the continuation checkpoint. No PR is created.

Default generic payload selection, bind payloads, idle REPL behavior, other
releases/platforms, non-ASCII owner-message framing and session database reporting
remain unqualified. Other failing modules and the full valuable feasible-module
inventory remain in scope; the goal stays active.
