# November 9 container module verification follow-up

The current verified checkpoint is **83 production runtime modules, 30 families
and 403 functional cases**. Every selected result has the exact expected count,
zero failures/pending/outside-example errors, matching current recorded input
hashes and successful owned cleanup. The repository-wide campaign remains active;
most modules still await individual feasibility review and functional testing.
The earlier published checkpoint was 71 modules, 25 families and 311 cases.

The local environment reports Docker Engine 29.9.2 and Compose 5.6.1. Functional
RSpec durations below include console startup and independent native controls;
they are not estimates of individual module execution time. No full repository
RSpec run was used locally, and no pull request was created.

## Authoritative DNS

The real vendor BIND 9.20.30/Alpine 3.24.2 image is digest-pinned. Independent
named-checkconf, dig and nsupdate controls establish authoritative records,
IPv4/IPv6 TCP/UDP, allowed/refused AXFR and unsigned updates, missing/wildcard/
reverse records and repeated add/read/delete behavior. Recursion and forwarding
are disabled; queries stay in the owned .test zones or test refusal on .invalid.

The parent 28-case suite passed with exact counts, zero failures/pending/outside
errors, matching inputs and owned cleanup at
`tmp/module-target-tests/20261109T115940-3c7bd2/dns/` (82.85s).
It covers enumeration, dynamic updates and one unspoofed scanner request per
host. Native stdlib queries and AF_PACKET capture establish actual request/reply
Ethernet-without-FCS lengths: IPv4 78/154 and IPv6 98/174 bytes for the TXT probe.
The suite also covers trailing-dot names, mixed batches and mapped IPv4 endpoints.

Separate worktrees reproduced and fixed:

- Scalar RHOST inline arguments being rewritten to RHOSTS even when only RHOST
  was registered (`fc8bf648400`). Alias behavior for ordinary scanner modules
  remains covered by focused parser tests.
- IPv6/mapped-address and trailing-dot amplification accounting (`b0743d4383d`).
- AXFR completion when both SOAs occur in one message, short/closed TCP framing,
  and nil-socket nameserver failover (`b022d462f70`, `0c68b2b7edc`). Native BIND
  transfers 13 records in one length-prefixed message, including both SOAs.
- Empty TXT/SRV inspection despite typed values being parsed (`d9fa592b18a`).
- Dnsruby positive cache state surviving resolver instances and misleading
  subsequent update/delete operations (`de6c7015656`); this module now requests
  fresh authoritative state without changing the global cache.

Initial fixture failures included invalid retry options, incorrect endpoint fields,
blank optional source addresses and Ruby keyword handling. Those were corrected
before classifying module defects. The blank SRCIP diagnostic selected the spoof
branch but failed source validation before transmission. No spoofed packet or
flood was used. Real negative/update outcomes remain asserted.

The combined DNS/parser/cron unit run passed 365 examples with two existing
pending vendored RR examples. The broader console group also had two DB-count
failures that reproduced with the original parser/specs; that investigation did
not establish a new parser regression. Native evidence and before/after reports
are retained in `tmp/dns-amp-evidence/`, `tmp/dns-axfr-evidence/`,
`tmp/single-rhost-parser-evidence/` and `tmp/dns-update-cache-evidence/`.

TSIG, pivots/proxies, huge or strictly validated incomplete transfers, arbitrary
wire extensions and database reporting remain unqualified. Fragmentation tests
are deterministic unit boundaries; live fragmented transfers were not qualified.

## Linux collection

The Ubuntu 22.04.5 profile uses real root/UID 1000 accounts, genuine installed cron,
network tools/OpenSSH configuration, generated SSH keys and a namespace firewall
rule. Native reads provide the oracle. NET_ADMIN is confined to this target's
namespace; no host network/socket/sysctl or privileged mode is used. Neither cron
nor sshd runs, so no scheduled execution or SSH service behavior is claimed.

Twelve cases cover system, network and protection collection over both declared
session types, shell and Meterpreter, as both users. Every case starts a fresh
actual payload session, waits for its completed bootstrap event, and proves its
real identity through native ownership of a session-created file. Loot matches
actual bytes, accounts/packages/crons and configuration; interfaces, a listener,
SSH key material and permitted/denied firewall collection are checked.

Root cron collection genuinely saved the account-name Array after executing
crontab commands. The isolated baseline was 4/2; the focused repair is
`e4352c31365`. The worker after-run passed 4/0 and the final focused source passed
14 examples (seven owning regressions plus seven existing shared examples).
Its diagnostic 180-second initial startup wait remains outside the repair commit.
The parent uses the normal startup helper and passed the full 12 cases, including
both users' cron jobs for root and only the current user's jobs for nonroot.
Current-source revalidation passed again at
`tmp/module-target-tests/20261109T115940-3c7bd2/linux_system/` (503.73s).

The original Linux session profile also passed its eight cases after extraction
of the shared identity-aware session helper. A failed experiment reused sessions
across examples even though reset kills them; a later 40-second command wait was
also insufficient for large collection loops. Fresh sessions and explicit bounded
180-second collection waits correct those harness issues without reducing data
assertions. The family keeps its ten-minute overall bound. Missing-file errors
are checked against native absence, and firewall denial against real permissions.
Other distributions, host kernels, security products and SSH directory combinations
remain unqualified. Evidence is under `tmp/linux-cron-evidence/`.

## VNC

Actual x11vnc 0.9.16/Xvfb services offer None or password security over RFB 3.3,
3.7 and 3.8. Independent Python/DES clients complete authentication and read the
actual 320x240 ServerInit desktop. Native controls also verify the eight-byte
password equivalence and incorrect-password rejection.

The parent 20-case profile passed with stable inputs and cleanup at
`tmp/module-target-tests/20261109T115940-3c7bd2/vnc/` (80.16s). It includes repeated
None detection, protected negatives, correct/longer/incorrect/blank passwords,
unsupported None for the password scanner, and real unrelated HTTP negatives.
This result includes the metadata snapshot correction described below.
Apple ARD, RFB 4.001, TLS/vendor servers, desktop control and DB persistence remain
unqualified. ARD root-account mutation requires an actual affected macOS target;
ordinary Linux VNC success does not establish that behavior.

## WebDAV

The pinned Apache 2.4.62 profile independently proves genuine DAV discovery,
public/Basic-authenticated/read-only/non-DAV policies, depth-one listings and
repeated native writes/readback/removal. Initial native controls caught wrong
filesystem ownership and a read-only rule that actually allowed writes; these
were fixture errors. An early 18-case run was also contaminated by an inline
newline; corrected file inputs produced a stable 19-case baseline with eight
actual module failures.

The listing repair (`9c07e311554`) fixes a port-only Host authority, omitted Depth
being refused as infinity, and prefix-specific XML matching. It uses the existing
XML response parser, preserves the stored note's one-element Array and exposes
DEPTH 0/1/infinity with default 1. Explicit infinity retains the former request
scope; successful recursive operation remains unqualified. Native raw controls
establish 400 for the port-only Host, 403 for omitted/infinite Depth and 207 for
normal depth-one requests. An actually empty Host was accepted, so the verified
Host diagnosis is specifically the invalid port-only authority.

HTTP file verification (`b4b6b7962f3`) now requires successful mutation status and
literal body readback, respects explicit extensionless names and distinguishes
absence from unreadable responses. Original code missed stored regex/multiline
contents and reported false upload success from 404/error-page or header matches.
Deletion retains its expected-content guard and requires verified absence rather
than a changed body. Binary/Unicode encoding-label boundaries are unit-only.

The isolated listing suite changed 4/3 to the unchanged original 4 passing cases,
plus two separately added depth controls (six after cases). The identical HTTP
PUT suite changed 11/5 to 11/0 with only the module input hash changed. The combined
parent 22-case profile passed, current hashes and cleanup included, at
`tmp/module-target-tests/20261109T122038-44d496/webdav/` (163.96s). It also proves a
denied overwrite of an existing matching file cannot count as an upload. Combined
focused tests passed 53 examples; no new module-doc diagnostics were introduced.
Captures include their source/provenance and explicitly distinguish derived
parser variants. Reports are under `tmp/webdav-listing-evidence/` and
`tmp/http-put-evidence/`. TLS/Digest, other servers, successful recursive scans,
locks/MOVE/COPY, executable uploads and persistent reporting remain unqualified.

## Harness corrections and revalidation

CouchDB native controls implicitly retried timed-out DELETE requests. Real server
logs show an initial 200 followed by a replayed 409 for the same old revision.
The control now disables implicit retries, uses a bounded ordinary read/write
wait and re-reads revisions on explicit conflicts. The intentionally non-protocol
native command trigger retains its separate shorter bound. All 26 CouchDB cases
then passed with current inputs and cleanup, including the final regression at
`tmp/module-target-tests/20261109T115940-3c7bd2/`.

The first broad revalidation exposed another setup race: after the prompt,
Framework could still rewrite its metadata. The helper parsed one read, then cp
read the source again, allowing empty/incomplete seeds to affect later families.
Memcached failed before execution; subsequent native profiles also stopped in
metadata setup. Their module behavior is unclassified by those failures.

The corrected helper (`379ce1c8aab`) waits up to five seconds for incomplete JSON,
then atomically publishes precisely the validated bytes with its timestamp.
It retains normal Framework checksum validation. Six focused snapshot cases and
seven existing shared examples pass; fifteen inherited helper lint signatures
remain, with none added. The fresh Memcached four-case rerun passed.
The final broader rerun passed all 26 selected families at
`tmp/module-target-tests/20261109T115940-3c7bd2/`. Separate current-source results
qualify SMB, SMTP, WebDAV and MQTT, bringing the checkpoint to all 30 registered
families. Every retained result matches current input hashes. Earlier cold-console
startup 120-second failures under concurrent cold loads are setup failures; a
single invocation reuses metadata without copying credentials/settings/sessions.

## MQTT

MQTT now passes ten parent cases on genuine Mosquitto 2.0.22, with native
anonymous/password/client-ID/TLS enforcement and repeated message round trips.
Its original ten-case run contained one invalid positive client ID and one genuine
unrelated-service nil-response parser crash. Correcting the ID to fit the current
packet gem's MQTT 3.1 limit produced a stable ten-case/one-failure baseline.
The separate repair (`b5a34933484`) preserves valid accepted/refused CONNACK
objects, converts missing/invalid replies to contextual connection errors,
handles the expected error in module/scanner callers and closes probe sockets.
The identical worker matrix then passed ten cases, with only the three owning
production files changed. Focused regressions changed 26/15 failures to 26/0.
The parent passed all ten cases, current hashes and cleanup included, at
`tmp/module-target-tests/20261109T123936-11f886/mqtt/` (77.06s).

Forty-five independent native commands exercise actual broker policies, accepted/
refused CONNECT replies, MQTT 3.1 compatibility, MQTT 3.1.1 retained messages and
TLS with the explicit lab CA. Framework TLS uses SSLVerifyMode NONE solely for
the public self-signed fixture; certificate validation is outside this profile.
Captures include stdlib source and actual broker responses. Malformed/fragmented
reply boundaries are unit coverage; native TCP fragmentation, other brokers,
MQTT 5, mutual TLS/PSK, topic ACLs and DB persistence remain unqualified. Evidence
is under `tmp/mqtt-response-evidence/`. Operator validation of client IDs longer
than the current MQTT 3.1 packet gem's 23-byte limit remains a follow-up: the
invalid positive fixture exposed a packet-gem RuntimeError, and this campaign
does not add a different protocol version or claim that input is supported.

## Remaining qualification and CI

Six source-hashed individual reviews now record Linux/Windows kernel, macOS,
printer and Cisco firmware requirements. These identify genuine target needs and do not declare
all such modules universally infeasible. The inventory still contains 5,179 source
files, including payload/support components; most candidates await review.

The previous pushed `399d88` checkpoint's Verify job failed on certificate OID
conversion in `cert_request.rb` under Ruby 3.4. The same failure was seen at earlier
campaign checkpoints, but its initial-base attribution is unclassified. Lint and
seven service/session workflows passed. Meterpreter also failed: the mettle job
finished 51 examples with two timeouts in `post/test/search` over HTTP/HTTPS with
`minimal_uris_headers.profile` (seed 2239). Those transport/search failures remain
unclassified; passing container profiles do not establish a green CI result.
Raw failed logs are retained in
`tmp/module-container-ci-399d88-{verify,meterpreter}-failed.log`.

## Current-source result index

RSpec time includes native preflight and console startup. Evidence paths are
relative to this worktree and retained locally; the repository contains the
reproduction inputs and this summary, while generated console/target logs stay
under the ignored `tmp/` directory.

| Family | Cases | RSpec seconds | Evidence directory |
|---|---:|---:|---|
| apache_normalize_path | 16 | 46.86 | `tmp/module-target-tests/20261109T115940-3c7bd2/apache_normalize_path/` |
| axis2 | 12 | 252.55 | `tmp/module-target-tests/20261109T115940-3c7bd2/axis2/` |
| couchdb | 8 | 15.54 | `tmp/module-target-tests/20261109T115940-3c7bd2/couchdb/` |
| couchdb_exec | 9 | 195.70 | `tmp/module-target-tests/20261109T115940-3c7bd2/couchdb_exec/` |
| couchdb_legacy | 9 | 22.51 | `tmp/module-target-tests/20261109T115940-3c7bd2/couchdb_legacy/` |
| dns | 28 | 82.85 | `tmp/module-target-tests/20261109T115940-3c7bd2/dns/` |
| ftp | 13 | 30.11 | `tmp/module-target-tests/20261109T115940-3c7bd2/ftp/` |
| http | 14 | 14.51 | `tmp/module-target-tests/20261109T115940-3c7bd2/http/` |
| ldap | 10 | 77.87 | `tmp/module-target-tests/20261109T115940-3c7bd2/ldap/` |
| linux_post | 8 | 184.64 | `tmp/module-target-tests/20261109T115940-3c7bd2/linux_post/` |
| linux_system | 12 | 503.73 | `tmp/module-target-tests/20261109T115940-3c7bd2/linux_system/` |
| mariadb | 10 | 57.70 | `tmp/module-target-tests/20261109T115940-3c7bd2/mariadb/` |
| memcached | 4 | 70.17 | `tmp/module-target-tests/20261109T115940-3c7bd2/memcached/` |
| mongobleed | 11 | 48.68 | `tmp/module-target-tests/20261109T115940-3c7bd2/mongobleed/` |
| mongodb | 31 | 35.85 | `tmp/module-target-tests/20261109T115940-3c7bd2/mongodb/` |
| mongodb_legacy | 12 | 16.11 | `tmp/module-target-tests/20261109T115940-3c7bd2/mongodb_legacy/` |
| mqtt | 10 | 77.06 | `tmp/module-target-tests/20261109T123936-11f886/mqtt/` |
| mssql2019 | 15 | 17.56 | `tmp/module-target-tests/20261109T115940-3c7bd2/mssql2019/` |
| mssql2022 | 15 | 17.42 | `tmp/module-target-tests/20261109T115940-3c7bd2/mssql2022/` |
| mysql8 | 10 | 15.36 | `tmp/module-target-tests/20261109T115940-3c7bd2/mysql8/` |
| postgres | 9 | 17.43 | `tmp/module-target-tests/20261109T115940-3c7bd2/postgres/` |
| redis | 22 | 123.72 | `tmp/module-target-tests/20261109T115940-3c7bd2/redis/` |
| rsync | 6 | 27.19 | `tmp/module-target-tests/20261109T115940-3c7bd2/rsync/` |
| smb | 20 | 63.92 | `tmp/module-target-tests/20261109T112229-7c8162/smb/` |
| smtp | 9 | 19.34 | `tmp/module-target-tests/20261109T112229-7c8162/smtp/` |
| snmp | 22 | 118.69 | `tmp/module-target-tests/20261109T115940-3c7bd2/snmp/` |
| ssh | 2 | 17.13 | `tmp/module-target-tests/20261109T115940-3c7bd2/ssh/` |
| tomcat | 14 | 139.16 | `tmp/module-target-tests/20261109T115940-3c7bd2/tomcat/` |
| vnc | 20 | 80.16 | `tmp/module-target-tests/20261109T115940-3c7bd2/vnc/` |
| webdav | 22 | 163.96 | `tmp/module-target-tests/20261109T122038-44d496/webdav/` |

The independent result selector rechecked each manifest's exact count, terminal
status, current recorded SHA-256 values and owned cleanup. Registration alone
does not qualify any additional module. These 403 cases are functional examples;
the focused unit-run counts above overlap through shared support and are not
added to that total.
