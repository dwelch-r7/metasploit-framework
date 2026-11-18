# MySQL authentication bypass/hash collection, 2026-11-18

The unchanged `auxiliary/scanner/mysql/mysql_authbypass_hashdump` owner passes
**16/0** across four genuine server configurations. Zero cases are pending and
there are zero errors outside examples. This adds one covered runtime owner and
four qualified profiles: campaign totals become **296 owners, 602 profiles and
4,202 historical functional cases**. The broader campaign remains active.

| Profile | Native configuration | Cases / failures |
| --- | --- | --- |
| `mysql_authbypass` | MySQL 5.5.23, real CVE-2012-2122 authentication bypass | 5 / 0 |
| `mysql_authbypass_open` | same binary, native `--skip-grant-tables` | 5 / 0 |
| `mysql_authbypass_policy` | same binary, loopback-only host grants | 3 / 0 |
| `mysql_authbypass_fixed` | MariaDB 11.2.2, correct-password access and wrong-password denial | 3 / 0 |

The [target guide](mysql_authbypass/README.md) contains the namespaced serial
command, pinned image and upstream build references. At most two containers run
at once, each capped at 384 MiB and 128 PIDs; app/reporting CPUs are 1/0.25.
No PR is created.

## Setup and native controls

The MySQL target is the unmodified Vulhub 5.5.23 linux/amd64 binary on Ubuntu
Xenial/glibc 2.23, pinned to image manifest
`sha256:5bbb7570f16526da1de61e84487daade5614eb2a9bfd28a87bcf4d6795b94463`.
The native client and server executable hashes are captured. Framework uses
Ruby 3.3.13 and ruby-mysql 4.2.1. MariaDB uses the already pinned official 11.2.2
image. No authentication implementation or response handler is replaced.

The [upstream target caveat](https://github.com/vulhub/vulhub/blob/b9999f23f7bd436f6b683a5fbd06555996848dfc/mysql/CVE-2012-2122/README.md)
requires checking the actual build/CPU behavior. The independent native client
first proves correct-password access and that the configured root hashes do not
match its deliberately wrong password. It must then observe both wrong-password
refusal and successful access as `root@%`. Initial feasibility observed 230
refusals followed by success on attempt 231. This is a genuine authenticated SQL
query, not a banner assertion. Root's numeric `123456` password also cannot equal
the owner's generated alphabetic value.

Before and after every profile, native controls prove the relevant contrast:
real bypass; access by a nonexistent account with grants disabled; rejection of
a non-loopback client by the host ACL; or correct-password access plus 64
wrong-password refusals on MariaDB. The grant-disabled fixture seeds ordinary
accounts first, shuts down normally and restarts using the genuine server option.
It qualifies immediate-login behavior, not CVE exploitation. SELECT-only and
SELECT-denied users are independently checked where authorization is enabled.
All account/host/hash snapshots remain identical across the module calls.

## Actual owner behavior

The final aggregate `20261118T142702-01faf5` records 16 real owner invocations and
31 entries into source methods `run_host`, `dump_hashes` and `report_hashes`.
Loaded owner hashes and the isolated console configuration are recorded. The
source module is unchanged.

- The vulnerable profile reaches the threaded bypass path for root, its repeat,
  a SELECT-only user and a user denied access to `mysql.user`. The first three
  save exact native rows; the permission denial saves no hashes or service.
- The grants-disabled profile reaches the immediate-login path four times,
  including a nonexistent username. All four dumps match the native rows.
- Protected-host and patched profiles refuse both executions without saving
  hashes or service records, retaining the same active console configuration.
- Every profile also rejects an independently closed TCP port without artifacts.

Seven actual CSV files retain all 77 expected rows, including five duplicate root
accounts, commas, quotes, spaces and an empty password hash. Fully blank anonymous rows are excluded by the existing owner. Expected values
come from native SQL hex fields; both the rows and CSV headers are checked. Seven
actual MySQL service records have the correct address, port and TCP protocol in
separate real Framework database workspaces. Negative calls create none. This
owner exports hashes as loot; credential-record creation is not claimed.

## Probabilistic acquisition and recovery

The source owner has a fixed 1,000-attempt limit. A positive case permits at most
three complete acquisitions only when the explicit exhausted-search outcome
occurs with no loot. Each such outcome is retained and followed by a fresh native
availability gate. Query, CSV, reporting and cleanup errors are never retried.
The final 16/0 aggregate needed no acquisition retries. An earlier four-case
calibration retained one exhausted run before native revalidation and successful
retry, demonstrating the single-invocation limitation rather than hiding it.

The first expanded 16/0 run checked idle sessions. Final verification strengthens
that SQL query to include every visible non-system client except its own query,
including unauthenticated connections. These server-side connections settle to
zero before teardown, without a harness socket kill. This selected recovery does
not prove every local descriptor or every possible process state. It specifically
checks the server clients left by this collector's threaded authentication work.

All 32 memory/PID event captures contain zero events. Docker inspection records
namespace labels and created object identities. Independent post-run inspection
confirms all 21 recorded containers, networks and volumes are absent. The task
namespace contains zero remaining containers. No unrelated container is stopped
or removed; cached images are retained.

## Evidence and limits

Immutable capsule `mysql-authbypass-functional-20261118T142702-01faf5` contains
201 files and 43 unchanged declared inputs, including complete console/native
captures, actual CSV files, reporting SQL, method traces and ownership/resource
audits. Its SHA256 manifest is
`306c6cc4a9ba98b359d5e67d7e80c943e8c53e436c726b1a82662452f821a1dc`.
The earlier expanded-run capsule manifest is
`16bcd6c798f35633a453bf8f2f6d74bd2ef82bcba930a802c5e50b36efc62c45`;
the first four-case capsule manifest is
`a6171c9c8a4a6a28e3303766d1ebc868366214c52182ef6444ac986fb63bfede`.
New Ruby helper/spec lint and Bash syntax checks pass. Module-document tidy has
4 pre-existing warnings and no new warnings. The static queue contains
5,179 source files, 4,298 pending selectable candidates and
223 pending documented container hints, with zero stale reviews.
Documentation/results are updated after sealing; runtime code is unchanged.
Human-authored Scenarios are preserved.

Different CPU/ABI builds require their own native gate. Current MariaDB denial
does not establish the historical MySQL 5.5.24 fix boundary. Other affected MySQL/
MariaDB releases, Unicode usernames, alternative authentication plugins, TLS and
other transports remain unqualified. The native acquisition bound and the owner's
probabilistic per-run limit remain practical restrictions.

**Summary:** Four bounded native configurations qualify the collector's covered
paths. **What looks good:** exact CSV/report persistence, both login paths,
authorization/host/patched/closed-port refusals, repeats and selected recovery pass.
**Concerns:** build-dependent and probabilistic behavior limits portability and
single-run reliability. **Suggestions:** retain the native gate when trying other
builds; qualify those independently rather than inferring vulnerability from a
version banner.
