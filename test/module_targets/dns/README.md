# Authoritative DNS module targets

```sh
bundle exec ruby tools/dev/run_module_target_tests.rb dns
```

The [vendor BIND image](https://hub.docker.com/r/internetsystemsconsortium/bind9/)
is digest-pinned as BIND9.20.30 on Alpine3.24.2. Real authoritative-only servers
serve deterministic `.test` zones and TEST-NET records. One permits transfers and
unsigned dynamic updates; the other refuses them. Neither provides external
recursion or forwarding. The [Compose IPv6 network](https://docs.docker.com/reference/compose-file/networks/#enable_ipv6)
provides both address families without host networking or a Docker socket.
Published TCP/UDP ports bind only to random IPv4 loopback ports.

Native named-checkconf, dig and nsupdate controls validate records, allowed/denied
policy, IPv4/IPv6 UDP/TCP, short wildcard/reverse cases and repeated update
readback/deletion. A Framework console on the owned network reaches real port53,
which the existing dynamic-update module requires. Fresh native queries distinguish
current authoritative data from the client's cached data.

Enumeration covers ordinary records, SRV, allowed/refused AXFR, CNAME/missing
names, a three-word dictionary, wildcard stop/continue, and a two-address reverse
range. Update cases cover A/AAAA/CNAME/TXT ADD, duplicate ADD, UPDATE, DELETE and
missing DELETE twice, denied changes, and explicit IPv4/IPv6 source addresses.

The scanner sends one unspoofed request per target for actual response measurement
or recursion refusal. Do not pass SRCIP, even as an empty string: that selects its
separate spoofing path. There are no floods, spoofed requests, external domains or
Internet-wide searches. Native Ruby standard-library queries and AF_PACKET capture
record actual Ethernet request/reply lengths independently from Framework.
These controls run as root inside the owned console namespace with its existing
NET_RAW capability; the actual Framework console uses the host UID/GID.

Scanner accounting retains its base Ethernet-without-FCS convention. IPv4 and
IPv6, trailing-dot names, mixed batches and IPv4-mapped endpoints are checked.
A valid small authoritative answer does not establish damaging recursive
amplification. VLAN tags, IP options/extensions, fragments, physical padding,
TSIG, pivots/proxies, huge zones and credential/note database persistence remain
unqualified. See the [campaign](../CAMPAIGN.md) for actual results/fixes and the
[shared guide](../README.md) for source provenance and owned cleanup.
