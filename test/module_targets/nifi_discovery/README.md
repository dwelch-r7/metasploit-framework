# Genuine Apache NiFi discovery targets

```sh
bundle exec ruby tools/dev/run_module_target_tests.rb nifi_discovery
```

Fifteen cases exercise the actual version and login scanners against official
digest-pinned Linux amd64 NiFi 1.13.2, 1.21.0 and 1.22.0 images, with unrelated
Apache HTTP and an ephemeral reporting database. The shared target components
live in `../nifi/`. No service response or authentication endpoint is simulated.

NiFi 1.13.2 uses its ordinary unauthenticated HTTP mode. The newer images use
self-signed HTTPS and their native single-user provider. `accounts.env` contains
public, artificial fixture credentials and a sensitive-properties key. Native
controls independently verify real UI script versions, API versions, accepted
and rejected authentication, authenticated identity and UID/Java. Both native
clients and modules use the configured NiFi hostname; module `VHOST` matches the
allowed proxy-host setting. Certificate verification is disabled for these local
self-signed fixtures; trusted-certificate behavior is not qualified here.

The missing application path really returns HTTP 200 with a branded "Did you
mean" HTML page and a browser meta-refresh. It contains no NiFi namespace script.
The tests require correct refusal rather than assuming a 404 or following a
browser refresh. Unrelated genuine Apache content is independently checked.

Ordinary cases repeat, including successful and rejected logins. Direct SQL
checks complete credential/service/origin/workspace graphs, exact account bytes,
SUCCESSFUL status and a validation timestamp. Repeated logins must not create
duplicates, and two workspaces remain isolated. The installed credential schema
has no persisted login-proof column; actual native responses and console output
remain external evidence. No such column is invented.

Targets use Docker's ordinary owned bridge, loopback-only random published
ports, init and an unprivileged NiFi user. No host network, socket, privileged
mode or host data mount is used. Ordinary Docker egress is not blocked. The
existing runner records inputs/results/images and removes its own project and
volumes; initial native preparation and module failures are retained separately.

The `vulnerable`/`fixed` service labels refer to the H2 URL issue addressed in
1.22.0, not to a claim that either scanner exploits it. Processor execution and
credential gathering require their own functional qualification. This profile
does not qualify Windows, IPv6, LDAP/OIDC/client-certificate authentication,
other releases, every brute-force option or full TLS behavior. Existing human
module Scenarios are retained; this guide contains no invented console results.
