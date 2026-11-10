# Gogs repository execution targets

The profiles define 25 functional cases. Native gates precede module assertions;
retained campaign reports record the exact verified inputs and actual outcomes.
The expected case count alone is not a qualification result.

The targets use authentic pinned Gogs images and their vendor entrypoint, with
SQLite, genuine HTTP Git, native users and a real Apache subpath proxy. No
protocol handler is substituted. The Framework container is also the native Git
client and payload listener, so the profile never needs an extra client service.
All accounts, passwords and tokens are artificial public lab material. The account
source is `accounts.tsv`; production credentials must never be used here.

## Profiles and resource limits

| Family | Selected cases | Running containers | Target scope |
| --- | ---: | ---: | --- |
| `gogs_hooks` | 10 | 4 | 0.12.3 root; 0.14.3 `/gogs/`; real Apache root |
| `gogs_rebase` | 10 | 5 | 0.14.2 root and `/gogs/`; reporting PostgreSQL |
| `gogs_rebase_fixed` | 5 | 4 | 0.14.3 root; forced and default AutoCheck negatives |

Run only one family per invocation after the campaign coordinator grants the
serial slot. The Framework limit is 1 GiB/1 CPU; each Gogs target is 256 MiB/0.5
CPU; Apache is 64 MiB/0.2 CPU and reporting PostgreSQL 128 MiB/0.25 CPU. The peak
five-container profile is 1,728 MiB/2.45 CPUs. No privileged containers, host
sockets, external Git servers or host network mode are required. Gogs SSH is
disabled. Published HTTP ports bind random loopback ports. Target state lives in
owned `/data` and `/backup` volumes removed by the existing runner.

```bash
bundle exec ruby tools/dev/run_guarded_module_target_tests.rb gogs_hooks
# After complete teardown and a separate serial grant:
bundle exec ruby tools/dev/run_guarded_module_target_tests.rb gogs_rebase
# After complete teardown and a separate serial grant:
bundle exec ruby tools/dev/run_guarded_module_target_tests.rb gogs_rebase_fixed
```

The existing runner keeps its 120-second service/console readiness bounds and
600-second family bound. If actual native work makes a profile exceed them, the
result remains unqualified; preserve the evidence before splitting the matrix.

## Native prerequisites and evidence

`native_probe.py` uses standard-library HTTP/cookies and actual Gogs CLI, Git and
OS operations. It records separate stdout, stderr, exit status, timing, original
HTTP bodies and real API/UI requests. Before module assertions it requires:

- The exact CLI version/help, expected configuration, git UID 1000 and real Bash,
  curl, Git, base64 and file tools. Modern CSS commit hashes must match the
  version fingerprints, with root and subpath routes both reachable.
- Successful native token authentication for each account; rejected passwords;
  actual read-only administrator web access versus ordinary-user refusal; granted hook
  permission; zero repository quota; private repository read/write/outsider
  policy checked with real Git pushes and HTTP access.
- Genuine hook execution or refusal, real divergent Git histories and pull
  requests, vulnerable rebase command proof, fixed/disabled nonexecution, and
  the installed Git package's ordinary `--exec` behavior independently.
- Actual token creation credentials authenticate before UI revocation and fail
  afterward; the surviving baseline credential stays valid. Token API rows are
  joined to real authenticated UI IDs. The 0.12.3 list contains raw tokens;
  0.14.x lists stored digest prefixes that already fail authentication before
  deletion and cannot themselves establish revocation.
- A source-built static ELF executed by the git UID. Separately generated
  Framework Bash/Meterpreter payloads must establish a native direct session,
  command nonce, UID and process shutdown before exploit session assertions.
  Rebase Bash payload refs also pass the actual local Git ref-format check.

The native observer is not an oracle for arbitrary response codes. Any route,
CLI, quota or Git status mismatch first stops as an unqualified setup result.
Only the actual native policy can establish a module failure. Profile counts and
runtime remain provisional until those gates have run.

## Expected behavior and cleanup boundaries

Hook permission is configuration, including in 0.14.3. Administrator and an
explicitly granted ordinary user may execute hooks; an ordinary ungranted user
must be denied. This is not a claim that 0.14.3 fixed hook execution. The Linux
dropper retains the owner's ordinary Bourne stager and x64 Meterpreter payload.
No Windows hook or rebase target is qualified by these Linux containers.

Rebase compares 0.14.2 with the vendor's 0.14.3 fix for
[CVE-2026-52806](https://github.com/gogs/gogs/security/advisories/GHSA-qf6p-p7ww-cwr9)
and [the upstream repair](https://github.com/gogs/gogs/pull/8301). Both own and
existing repository methods are exercised with genuine commands and sessions.
The fixed forced path must reach the actual malicious branch/PR/merge attempt,
yet produce neither the command nonce nor a session. A version banner, merge
response, reported vulnerability or session count alone never proves execution.

Each execution case repeats twice using fresh module instances against persistent
target state. Same-instance module reset is not covered. Own repositories must
disappear automatically.
Existing repositories use an explicitly fresh native seed for each iteration;
refs and actual remaining repository state are recorded before the operator
removes the seed. There is no claim that the same corrupted repository can be
exploited twice unchanged. Closed PR history, unreachable objects and Gogs local
merge caches are retained as observed state, not silently equated to live refs.

The rebase owner documents that its created `msf_*` API token persists. Tests
record that token and warning before a separately identified native UI operator
revocation. Any remaining repository is captured before the operator deletes it.
Operator restoration does not count as module cleanup. Actual target and local
module temporary paths, live process identity, known payload PID and listener
absence are checked independently. Shell proof sends an explicit target exit and
requires native PID absence before supported operator host-session closure;
that closure is not labeled automatic deregistration or a forced target kill.
Teardown then removes only owned resources.

The original module's explicit `TARGETURI` contract and subpath behavior remain
strict test inputs. An unknown-option warning fails positive cases. No owner is
modified preemptively to satisfy the lab.

## Retained nonfatal target diagnostics

The vendor default picture paths are relative to the Gogs installation. These
fixtures can log avatar-generation permission errors at `/app/gogs/data` even
though application data is configured under owned `/data`. The original logs
retain those warnings. Actual authentication, Git, hooks and native payload
controls must pass independently; avatar generation and upload are outside
these profiles. The matched module comparison keeps this configuration fixed.

## Provenance

`provenance.json` records primary-source URLs, response hashes and official image
identities researched on 2026-11-10. Vendor image identity and configuration still
require native verification. 0.14.2 and 0.14.3 are digest-pinned official images;
`gogs/gogs:0.14` is floating and was already 0.14.3 at research time. Existing
human module Scenarios are preserved and are not generated by these tests.
