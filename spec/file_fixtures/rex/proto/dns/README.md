# Native AXFR capture

`bind_9_20_30_axfr.json` contains the original DNS messages captured on
2026-11-09 from ISC BIND 9.20.30 on Alpine 3.24.2, using this image:

`internetsystemsconsortium/bind9:9.20@sha256:66092edb53c081fa11b1fa8219e99065b0f497cb38f568ba789702a4c10e2590`

The authoritative `module-target.test` zone had 13 transfer records, including
both SOAs in one DNS message, a TXT marker, and an LDAP SRV record. Addresses
inside the zone use documentation networks. The second server served the same
zone with transfers refused. The refused response has RCODE 5 and no answers.

The source capture script uses Ruby's standard `Resolv` library, independently
of the Framework resolver. Run it against a published TCP port for each server:

```sh
ruby spec/file_fixtures/rex/proto/dns/capture_axfr.rb 127.0.0.1 PORT open
ruby spec/file_fixtures/rex/proto/dns/capture_axfr.rb 127.0.0.1 PORT closed
```

The fixture retains the request and complete length-prefixed response bytes
from those two commands. Endpoint metadata and nondeterministic Ruby object
inspection strings were omitted. The framing fragmentation and multi-message
variants in the resolver spec are derived tests, not additional native captures.
