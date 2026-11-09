# SNMP targets

```sh
bundle exec ruby tools/dev/run_module_target_tests.rb snmp
```

This builds the actual Ubuntu Net-SNMP 5.9.1 daemon and native CLI tools
(`5.9.1+dfsg-1ubuntu2.10`) on a digest-pinned Ubuntu base. The runner records the built image ID and native
package version. Public disposable communities are `public` (read only) and
`private` (read/write), for SNMP v1/v2c over UDP/TCP. Only a random loopback TCP
port is published; Framework runs on the isolated project network for both
transports. No host network, extra capabilities or Docker socket is needed.

Native CLI controls validate identity, rejected credentials, read-only denial,
actual writes and restoration independently for each protocol/version. Module
tests cover community/access detection, Linux host enumeration and repeated
string SET operations using canonical and leading-dot numeric OIDs with native
readback and restoration. The agent's real
container processes, interfaces and OS tables provide enumeration data.

The [Net-SNMP configuration guide](https://www.net-snmp.org/docs/man/snmpd.conf.html)
describes community access and writable system objects. The lab intentionally
does not configure sysContact in the file: that would make it read-only even for
the write community. No Windows/vendor-specific MIB, SNMPv3, trap, IPv6 or saved
credential qualification is implied. See the [campaign](../CAMPAIGN.md) for actual
results and [shared guide](../README.md) for evidence and cleanup.
