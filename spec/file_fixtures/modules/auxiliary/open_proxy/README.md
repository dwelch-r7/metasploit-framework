# Native proxy evidence

`native.json` preserves the nine operations from the parent's real Apache
2.4.62 proxy preflight `tmp/msf-target-proxy-native-ce396f30/native.json`, with
the producer checksum and provenance. No responses are simulated. Ruby
Net::HTTP independently uses GET forwarding and CONNECT followed by actual TLS,
then verifies the origin bytes and certificate subject. TLS success entries
are HTTPS origin responses after a working tunnel, not raw CONNECT response
bodies. Refused CONNECT entries retain Net::HTTP's actual refusal code.

The three native working CONNECT forms underpin request-authority regressions.
Additional IPv4/IPv6, scheme, path and invalid-input cases are derived parser
boundaries. They do not claim extra native target or IPv6 transport coverage.
