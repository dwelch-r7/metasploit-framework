# FTP bounce scanner validation, 2026-11-11

The checkpoint is **193 qualified modules, 138 profiles and 1,526 functional
examples**. The [FTP bounce profile](ftp_bounce/README.md) adds one module and
ten examples. Registration covers 195 sources; 309 documented container hints
remain pending review. The broader campaign remains incomplete. No production
module change or PR is made.

Four containers are capped at 960 MiB and 1.3 CPUs: two ProFTPD relays, one real
Apache destination and canonical Framework. The default test network is internal;
targets also use the existing second-network pattern for random loopback port
publishing. No host namespace or additional capability is required. Limits are
caps, not measured peak-memory claims.

## Target identity and normal configuration

The unchanged [FTP fixture](ftp/README.md) builds the relays from Ubuntu 22.04
digest `sha256:076e7bf82319619f28dd0aa9c02ab34b055ad37100395b4f49a2ffba04fb5e11`.
The actual installed package is `proftpd-core 1.3.7c+dfsg-1ubuntu0.1`, reporting
`ProFTPD Version 1.3.7c`. The binary SHA256 is
`2b79445608f9b0ea96e4f36e7c9508487d1e096bfeee7a83c1029affc4c33cdd`,
unchanged before/after. Distribution packages resolve during the shared build;
these observations do not pin every future archive resolution.

Observed relay image IDs are
`sha256:bea72cbd058e8ee7198f81b36405200fd576f18a15f13c650bcaeca49f2fe364`
and `sha256:3247464b8b5ee48cef074d2348f82bd0ec3b2d2174c4e0345a0c43888388a7b8`.
Their filesystem-layer lists match exactly. Supported `AllowForeignAddress`
settings differ at runtime in both server and anonymous contexts. The
[official directive documentation](https://github.com/proftpd/proftpd/blob/v1.3.7c/doc/modules/mod_core.html#allowforeignaddress)
describes foreign-address control and the separate low-port restriction.
Application handlers are unchanged.

The Apache 2.4.62 destination is pinned to
`sha256:4c7788695c832bf415a662dfb5160f1895e65fc65c025e85f436ee2c9e7d7f3e`,
observed image `sha256:f81fca8b7f7458d67b07f14dca30fb827ab36563ab98f40a222a3045d9a56b32`.
It normally listens on ports 80, 8080 and 8082; 8081 is closed.

## Independent native controls and preserved failure

Before/after Python ftplib controls perform local and anonymous logins, retrieve
the exact owned marker file and issue actual foreign PORT/LIST commands. Both
high ports must receive data through the permissive relay, while the protected
relay rejects the foreign address. The closed destination port produces 425;
low port 80 is refused by relay policy despite independent HTTP 200 proof that
it is open. Incorrect local passwords produce 530. Native controls also bind
actual binary/configuration identity and leave the marker file unchanged.

Destination logs independently prove new connections and directory-listing data
arrived from the actual relay IP at each high port. Apache returns HTTP 400 for
this genuine non-HTTP input. Its normalized `%r` field contains the first three
listing fields, `-rw-r--r-- 1 0`, rather than the later filename. The assertion is
derived from that actual capture; it does not claim full listing content from
the access log.

Initial run `104912-0f4188`, source `9341311d331`, passes the native FTP/HTTP
controls but its host matcher incorrectly requires the filename in `%r`. The
before-all assertion prevents every owning call; ten inherited RSpec failures
are not ten module defects. The manager exits one, root observes genuine cold
metadata and ten exact cleanup queries pass. Its immutable 92-file package has
manifest SHA256
`644a985fd096eec8274b39136dbcdc9ffdcf4ea35fb43771e3b0d7bf28a15825`.
The corrected matcher retains exact source-IP, local-port and received-prefix
checks. Module FTPDEBUG output is also retained for real protocol replies.

## Complete owning results

Run `20261111T105302-3bb340`, source
`c7753f3df2ea3cf4dc3436c065b51e575f1f93b0`, passes **10 examples with zero
failures, pending or errors outside examples** in **60.135969 RSpec seconds**.
The actual manager and root observer both terminate zero, with both complete
native phases passing and four received native transfers per phase.

Twenty unique owning-call records verify:

- Repeated anonymous and authenticated scans through the permissive relay.
- Mixed open/closed lists, ranges with a closed middle port and reversed input lists.
- Protected-relay and rejected-password refusals without destination reports.
- The actually open low port remaining unreported under relay policy.
- A small configured delay preserving successful scanning.

The library normalizes explicit input lists: reversed inputs are not a claim
that the module executes ports in reverse order. All eighteen reported open
ports match eighteen newly received destination connections. Thirty-eight real
service-reporting API calls comprise twenty relay FTP services and eighteen
destination host/port reports. The shared NTP observer retains arguments and
calls the production methods; its historical filename remains
`ntp-reports.jsonl`. SQL persistence is not claimed.

Root independently verifies all 43 current input hashes, twenty separate owning
records, destination-source IPs/ports, API arguments, exact console port sets,
binary/configuration stability and the relay filesystem layers. The parent has
81 regular files. Actual four-role limits, the first console prompt, isolated
BOOT and two fresh metadata snapshots are observed, with no first seed. Ten
root queries prove the exact four containers, two networks and label inventories
absent, with global containers empty. No volumes or sessions are created.

The immutable 127-file complete source/run package has manifest SHA256
`ebfad96208b11bbd2e67b854044a5bce73f813335924e8a8db758f69b0cb0055`.

## Review and remaining scope

- **Summary:** the unchanged scanner passes its ordinary ProFTPD IPv4 paths.
- **What looks good:** genuine active data connections, two authentication modes,
  policy/closed negatives, mixed ports, repeats and observed reporting arguments.
- **Concerns:** no new code concern remains for this scope. IPv6 is explicitly
  unsupported by the module. Other FTP products, invalid-option contracts,
  jitter timing, alternate reply coalescing and SQL persistence remain separate.
- **Suggestions:** continue to new valuable targets rather than infer all FTP
  implementations or packet timings from this one product configuration.

Two changed Ruby files pass syntax/RuboCop, both Python files parse, resolved
Compose limits and local links are checked, and the module's existing human
Scenarios remain unchanged. Documentation lint retains the same five existing
Scenario-formatting warnings and missing-Options information as the base;
no new diagnostic is introduced. No full Framework suite is run.
