# Native osTicket file-read target

These opt-in targets run the untouched official osTicket release, MariaDB and a
separate Framework reporting database. They publish ephemeral loopback ports.
The pinned WordPress image supplies PHP/Apache extensions; its WordPress
entrypoint is bypassed and no WordPress application is installed. The genuine
osTicket HTTP installer creates the database and staff account. Vendor model APIs
create a confirmed client and disposable tickets. Mail is disabled in this lab.

Profiles: `osticket` (1.18.2), `osticket_prefix` (1.18.2 at `/support`), and
`osticket_fixed` (1.18.3). Each stack has three capped containers; run them serially.
Use the shared guard and a namespace. Cleanup removes only the created Compose
project. Preserve every unrelated container.

Fetch the independent researcher payload generator before the first run:

```sh
mkdir -p tmp/module-target-osticket-sources
curl --fail --location 'https://raw.githubusercontent.com/horizon3ai/CVE-2026-22200/06a50ca2b192ee91d1cc6cb60a3b4553392c2654/osticket_ticket_payload_gen.py' \
  --output tmp/module-target-osticket-sources/osticket_ticket_payload_gen.py
printf '%s  %s\n' '2da894d6368ed3fdf37862c60bb3c6af83df7167e8b62085850fd510034f685c' \
  tmp/module-target-osticket-sources/osticket_ticket_payload_gen.py | shasum -a 256 --check
MODULE_TARGET_NAMESPACE=my-osticket-tests bundle exec ruby tools/dev/run_guarded_module_target_tests.rb osticket osticket_prefix osticket_fixed
```

The PoC is cached locally and hashed as a runtime input. Container builds fetch
checksum-locked official release ZIPs. No host Python packages are required.
Poppler in the target independently decodes real PDFs; the module's PDF decoder
is not used by the native control.

Before and after the module cases, both portals reject a wrong password, accept
the lab account, expose its protected ticket and produce a valid ordinary PDF
containing the ticket text. A fresh native ticket then carries the independent
Base64 file-read payload. Its exact encoded canary must occur in image pixels on
1.18.2 and must be absent on 1.18.3. Every shipped vendor PHP file is compared
against the source archive. The controls delete their own tickets. Module cases
use separate tickets and recover those tickets through the genuine vendor API.
Cgroup memory/PID events are checked for all three services.

Credentials are public fixtures: staff `module_admin`, client
`module-client@example.test`, password `Module-target-password42!`. Do not expose
these vulnerable targets outside the local lab.

A successful native PDF does not imply a working module. The original module's
Base64 decoding failure and the independent payload's plain/Deflate truncation
are tracked separately. The [verification report](../VERIFICATION-20261118-osticket.md) records strict
results: affected root/prefix each6/2, fixed3/0. Complete recovery and credential
persistence remain unqualified; the affected profiles intentionally exit nonzero. Human-authored module Scenarios are not
changed by this lab.
