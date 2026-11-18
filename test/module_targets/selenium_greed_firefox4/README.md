# Selenium Firefox execution

This opt-in target exercises the real
[execution owner](../../../modules/exploits/linux/http/selenium_greed_rce.rb)
against stock, digest-pinned Selenium Grid 4.27.0 / Firefox 133.0.3 on
Linux/amd64. The Compose fixture, native controls and functional spec are kept
beside this guide; the [module documentation](../../../documentation/modules/exploit/linux/http/selenium_greed_rce.md)
links here. Registration alone does not qualify a profile.

```sh
bundle exec ruby tools/dev/run_guarded_module_target_tests.rb selenium_greed_firefox4
```

The host needs the repository's working Ruby bundle, Docker Compose and Python
3. One target container runs at a time, capped at 768 MiB / 0.5 CPU / PID512,
with init, equal memory/swap and 128 MiB shared memory. The console runs on the
host and the published WebDriver port binds to loopback. There are no target
source overlays, custom request handlers, privileged containers or Docker socket
mounts. No extra image build is needed.

## Native prerequisites

Before owning execution, a real browser must load a DOM and execute JavaScript.
An independent WebDriver client then supplies a shell MIME handler and proves
actual shell-canary bytes and UID1200. The 5-second native page-load deadline
returns a genuine navigation timeout while the handler executes; deletion must
release the sole browser slot. The control removes its exact downloads and
marker. Both controls run again after all selected owner cases.

The owner's Firefox path now supplies its own bounded page-load timeout and
ensures deletion of an acquired browser. `FirefoxPageLoadTimeout` defaults to 5
seconds and must be positive and below the effective `HttpClientTimeout`
(20 seconds when no positive override applies). The profile uses HTTP30.
This navigation bound does not bound browser startup or the entire exploit.
The original profile ZIP and payload builders remain in use.

## Functional cases

The spec requests five cases:

- Actual `check`, followed by a Unix command with exact native file bytes/UID
  and an empty browser slot. This sessionless canary explicitly permits
  `AllowNoCleanup`; the harness removes only its exact task-owned marker.
- Python in-memory Meterpreter with automatic browser selection and AutoCheck,
  repeated through the same console configuration.
- Bash command shells with explicit Firefox and AutoCheck disabled on a fresh
  console configuration, then repeated.
- Linux x64 Meterpreter through the WGET HTTP fetch adapter, with AutoCheck and
  a repeat. The selected fetched executable must already be absent at recovery.
- A page-load timeout equal to the HTTP deadline, rejected before browser
  creation or command execution.

Real session APIs must create/read observable proof: Meterpreter writes a file
and reports process/identity/system information; shells execute their public
command API. Independent Docker observations confirm exact file bytes, UID1200
and the live PID identity. Meterpreter channel sets must agree before/after.
Each session receives a graceful exit, and the recorded native PID must disappear
without operator signals before another exploit. Framework sessions/jobs and
browser slots must be empty after each execution.

A passive Ruby TracePoint records actual owner calls and the generated download
script. It does not replace owner methods, responses or transports. Framework
clones exploit instances; repeating a console configuration does not claim
reuse of one execution instance. Known download scopes are snapshotted. Recovery
only removes newly created UID1200 files matching an observed owner-script hash,
plus empty new task-owned directories; pre-existing file bytes must agree.
The entire container/network is removed afterward. Logs, access times and the
whole filesystem/process table are not claimed unchanged.

## Evidence and limits

Native MIME/setup/optional optimized-archive reader failures, the initial
FileDropper gate and callback-helper errors are retained separately from owner
results. The optional source-archive reader does not attest Mozilla's optimized
archive; actual browser behavior is the prerequisite. The clean original/fixed
owner-only replay establishes the browser leak and repair independently of the
expanded session cases. Focused contracts disclose their transport doubles.
Human module Scenarios are preserved.

Only the exact selected Grid/Firefox version, platform and payload paths can be
qualified by this profile. Other releases, Chrome, Selenoid, authentication,
other architectures, transport loss and forced cleanup remain unqualified.
Consult the campaign verification record for actual completed results.
