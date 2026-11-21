# ProjectSend command delivery and settings preservation

The [command profile](projectsend_rce/README.md) runs **3 examples / 1 failure /
0 pending** in **77.43 seconds**, excluding container startup. Native prerequisites
and actual command delivery pass; complete option preservation fails. This is a
retained module defect, rather than a passing profile or a default-session claim.
No production module code changes in this tranche.

## Native prerequisites and actual execution

The profile reuses the unchanged, pinned **LinuxServer r1605-ls199 / PHP 8.3.9**
image, **MariaDB 10.11.9**, real HTTP installer and twelve source fingerprints
from the [check profile](projectsend/README.md). Only two capped services run:
application **384 MiB / 0.7 CPU**, database **256 MiB / 0.3 CPU**, equal swap caps,
temporary configuration/uploads/database storage and a random localhost HTTP
port. Normal application mail settings select SMTP at **127.0.0.1:9**; native
connection refusal is verified and these settings join the preservation baseline.
No package, optional extension, application patch or replacement endpoint is added.

Each exact command first passes the original `php/exec` producer on stock PHP
CLI. Independent registration/login then proves specific PHP extension denial,
unauthenticated restriction changes, genuine multipart upload, exact uploaded
source bytes, UID-1000 execution, self-unlink and portal-row deletion. Explicit
native fixture recovery removes its client and restores all baseline options.
The HTTP 500 responses after registration/option persistence are retained; the
native gate requires actual database, file and execution postconditions.

The original exploit runs twice on one console selection, first with AutoCheck,
then with AutoCheck disabled. Plain output and quoted Unicode/CRLF output match
exactly at UID 1000. Passive original-method traces record payload source, exact
command, generated PHP and raw multipart bytes. Each run tries the original 27
candidate filenames and receives exactly one executable URL response. Portal
rows and the physical upload inventory recover after production cleanup;
pre-existing user identity, role, activity and email fields preserve. The first check returns reason-bearing Appears;
the second run executes without a check. Proof markers are separately removed.

## Confirmed preservation failure

All **134 baseline option rows** are compared after each real exploit attempt,
before any deliberate fixture recovery. Both executions leave **136 rows** and
the same six changed or added names:

| Option | Before | After |
| --- | --- | --- |
| `clients_can_upload` | `1` | `0` |
| `clients_can_delete_own_files` | `1` | `0` |
| `clients_can_set_expiration_date` | `1` | `0` |
| `expired_files_hide` | `0` | `1` |
| `clients_new_default_can_set_public` | Absent | `0` |
| `section` | Absent | `security` |

Exploit setup and cleanup post general client/security sections, which persist
the section key and implicitly reset omitted checkboxes. Cleanup resets client
permissions to defaults, rather than recovering their original values. The
first failure remains in place through the second actual exploit; no intervening
fixture reset hides it. Two created, active client accounts also remain and are
recorded. Account removal is not claimed.

Only after retaining final raw state does explicit fixture recovery restore the
complete option baseline and then factory options. Configuration bytes and all
twelve application fingerprints match afterward. Containers and temporary state
are removed regardless of the failing assertion. Recovery does not change the
module verdict. Restoring unknown original client/security values needs further
investigation; resetting additional defaults would not establish preservation.

## Evidence and limits

The production module SHA256 remains
`6eb96c4110fa0a780948ebe196fbc14569766dfb88e63a093e8301ff471a3ce9`.
An earlier native-gated frame also has **3/1/0** in **86.00 seconds**, with both
commands succeeding and the same six-option difference. The final replay adds
physical-upload and pre-existing-user preservation assertions. Ruby syntax,
Python syntax and focused RuboCop pass without new offenses. The separate
[check qualification](VERIFICATION-20261121-projectsend.md) remains current.

One initial setup-only frame is retained separately: this Docker Desktop setup
does not publish a host port on the internal Docker network. It stops before
RSpec or module execution. The normal network plus ordinary loopback SMTP
configuration corrects that fixture issue. It is not a module failure.

Eight final cgroup captures have zero OOM/PID-limit events and unchanged
counters. Six are fully zero; the database memory-limit counter is **46 before
and after**, already present before native payload/owning execution. All nine
Docker objects from the three phases are independently absent, and both Docker
contexts are globally empty, including stopped containers. The prior 612-object
cleanup receipt is rechecked separately.

The audit reconciles **337 current declared input hashes**, retaining the prior
**110 fully passing cases / 32 profiles** separately from this failing profile.
No successful session is added. Default PHP Meterpreter, other payload families,
other releases, patched behavior and full settings recovery remain unqualified.
The complete valuable/container-feasible inventory goal remains active. No PR
is created. Codex prepared the fixture, tests and diagnosis; retained native and
owning execution supplies the reported results.
