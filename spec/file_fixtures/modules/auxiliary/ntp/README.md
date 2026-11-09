# NTP READVAR response fixtures

`readvar_packets.json` retains four unmodified complete UDP payloads from the
independent probe in `test/module_targets/ntp/wire_probe.rb`: genuine ntpd
4.2.8p15 replies for NTP versions 2, 3 and 4, and a BIND 9.20.30 DNS FORMERR
response to the same version 2 request. The source run and full native evidence
file SHA-256 accompany the packet Base64, individual digest and byte length.
The independent probe uses sequence 23; unit tests use that captured request
without editing its genuine response. Fixture hosts in unit examples use
TEST-NET-1. No operational NTP hosts or credentials were contacted.

Reproduce with the digest-pinned native lab and its independent stdlib probe:

```sh
bundle exec ruby tools/dev/run_module_target_tests.rb ntp
```

The retained capture is
`20261109T144445-29fa86/ntp/native-ntp-before.json`, taken November 9, 2026. The
real daemon provides kernel, processor, version and a configured information
variable. Time/frequency discipline is disabled, SYS_TIME is absent and no
external clock source exists. This is information-query qualification; it is
not time synchronization or spoofed traffic qualification.

The spec's malformed headers, changed flags/transaction fields, count overrun,
empty response and nonzero fragment offset are explicitly derived boundaries.
They are not extra native captures. Complete native datagrams include alignment
padding, which must remain in wire-size accounting while being omitted from
reported property data. Native replies also set the top two header bits when
the server clock is unsynchronized; validation must not reject those captures.

Field definitions come from the
[NTP control-message reference](https://www.rfc-editor.org/rfc/rfc9327.html#name-ntp-control-message-format)
and [RFC 1305 Appendix B](https://www.rfc-editor.org/rfc/rfc1305.html).
