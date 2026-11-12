# Pi-hole Top Domains command execution lab

The target uses pinned official Pi-hole images, their normal `/s6-init`
entrypoint, genuine PHP validation and gravity scripts, real SQLite and a local
one-domain blocklist. No HTTP handler or module method is replaced. Native
preflight must establish a working gravity update before module tests run.

Docker v5.5 contains Core 5.2.4, Web 5.3.1 and FTL 5.5; Docker tags do not identify
the web version. The [Web 5.5.1 hotfix](https://github.com/pi-hole/web/releases/tag/v5.5.1)
addresses [CVE-2021-32706](https://github.com/pi-hole/web/security/advisories/GHSA-5cm9-6p3m-v259).
The fixed profile uses the genuine Web 5.6 release in Docker 2021.09.

These historical Debian Buster images refresh APT metadata during ordinary
startup. The lab points APT at the Debian archive with signature verification
retained. Its release-date expiry check is disabled for the archived release.
No package is installed and no application source is patched. Bounded writable
metadata storage and the lighttpd user's log-directory ownership are explicit.

Initial automatic gravity refresh is disabled through the vendor's existing
environment option. Native setup then configures and fetches a small blocklist
from the target's own loopback HTTP endpoint. This exercises the normal database
and gravity pipeline without downloading external blocklists.

The planned serial selectors are `pihole_domains_fixed`,
`pihole_domains_unrelated`, `pihole_domains_vulnerable` and
`pihole_domains_noauth`. Functional qualification remains pending until their
acceptance results and independent teardown have been recorded. Native pilots
alone do not qualify the module.

Application profiles budget three containers at **1,152 MiB/1.45 CPUs**:
target 256 MiB/0.25 CPU/128 tasks, reporting PostgreSQL 128 MiB/0.2 CPU/64 tasks
and Framework 768 MiB/1 CPU/256 tasks. Only HTTP is published, on random loopback
ports. No DHCP capability, privileged container or host DNS port is required.
Run one profile at a time and remove each project before starting the next.
