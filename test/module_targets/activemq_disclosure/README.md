# Genuine legacy ActiveMQ JSP source lab

Run `bundle exec ruby tools/dev/run_module_target_tests.rb activemq_disclosure`
from the Framework root. The native gate and Framework results are separate.

The targets use genuine Apache 5.3.1 and fixed 5.3.2 archives on pinned Temurin 8
amd64, with native runtime 1.8.0_412. Historical publisher SHA1 and detached
signatures were verified against official Apache KEYS; the recorded SHA512 pins
those authenticated bytes. See the shared `../activemq_legacy/provenance.json`.
The genuine Apache 2.4.62 image is an unrelated endpoint. Ports publish randomly
on 127.0.0.1; no operator service or credentials are used.

[AMQ-2700](https://issues.apache.org/jira/browse/AMQ-2700) identifies the affected
5.3.1 and fixed 5.3.2/5.4.0 boundary. In the actual publisher configurations the
catch-all ResourceHandler base moves from `webapps/` to `webapps/static/`.
The native gate verifies real JMS/version/queue removal, normal compiled HTML,
three exact stock JSP source files via double slash, fixed/missing refusals and
an unrelated real HTTP200 body. No API or rendered/source response is simulated.
The stock anonymous HTTP policy is retained.

Eight examples require exact source-loot hashes on two repetitions for three
path forms/pages. Fixed, missing, unrelated HTTP404/200 and non-JSP HTML must not
be called source disclosures. Raw traces retain legitimate Java names inside
JSP data while Ruby/Framework errors remain failures. Loot lives in the isolated
console config and is retained as evidence. This family changes no target files
apart from independently created/removed native JMS queue state.

These cases target only Linux amd64 and plaintext HTTP. Windows,
TLS/IPv6, other versions and custom web context/filesystem policies remain
unqualified. The separate Windows directory traversal modules are not forced
onto this Linux target. FileServer/JSP execution has separate versions and gates.
