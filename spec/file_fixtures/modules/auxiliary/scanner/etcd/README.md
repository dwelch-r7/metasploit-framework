# Native etcd response captures

These exact HTTP bodies come from the owned native preflight in
`tmp/etcd-native-setup/native.log`, using digest-pinned etcd 3.4.35/3.5.18
and ordinary Apache content from `test/module_targets/etcd`. `captures.json`
records source profiles, operations, statuses and actual headers. Recursive
data is disposable Unicode/newline/empty test content. Authentication replies
contain no external account data. The native gate independently verifies the
server CLI version, values, accepted/refused credentials and disabled v2 API.

Unit examples with nil replies, alternate JSON types, omitted fields or altered
versions are synthetic boundary inputs derived from these captures, rather
than claims of observed server responses. The disabled-v2 404 body is reused
only as an HTTP-status boundary when testing version discovery.
