# LDAP protocol suite target

Run from the repository root:

```sh
bundle exec ruby tools/dev/run_module_target_tests.rb ldap
```

This lab reuses the existing Samba LDAP acceptance fixture, schema and seeded
LAPS account. Ubuntu and certificate-source images are digest-pinned; installed
OS packages may drift on rebuild. Native LDAP authentication must read the actual
LAPS value before Framework starts. The public account is `DEV-AD\Administrator`
with password `admin123!` in `DC=ldap,DC=example,DC=com`.

The existing suite opens a real LDAP session and runs queries, LAPS extraction,
shadow-credential reads and RBCD reads through session and direct-host paths.
The fixture runs only Samba's LDAP service. Its service advertisement deliberately
differs from a complete Windows AD controller; it cannot qualify Windows AD,
Kerberos, replication, write permissions, TLS or state-changing attacks.

Like the original fixture, domain provisioning requires `SYS_ADMIN` to store
`security.NTACL` extended attributes. A native provisioning attempt without that
capability failed before LDAP started. The container has no host network, Docker
socket or writable host-source mount. Only a random loopback LDAP port is
published. This is an additional capability requirement beyond the ordinary
service labs; review it before running the lab on a shared Docker host.

See [the shared guide](../README.md) for retained evidence and cleanup, and
[the campaign](../CAMPAIGN.md) for current qualification status. Creating a lab
does not establish that its module tests passed.
