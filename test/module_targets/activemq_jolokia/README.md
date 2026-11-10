# Genuine ActiveMQ Jolokia lab

Run `bundle exec ruby tools/dev/run_module_target_tests.rb activemq_jolokia`
from the Framework root. Native and Framework outcomes are recorded separately.

The family builds genuine Apache 5.19.3 and 5.19.4 publisher-checksummed archives
on a digest-pinned official Temurin 17 amd64 JDK. Apache's
[CVE-2026-34197 advisory](https://activemq.apache.org/security-advisories.data/CVE-2026-34197-announcement.txt)
identifies 5.19.4 as the branch fix. Its BrokerView validates nested vm URIs before
creating connectors. Binary and source archives were independently checked
against publisher SHA512 values before selecting the targets.

Brokers run as activemq with bounded JVM resources. Fixture changes expose Jetty
on the isolated network, assign distinct real broker names and deploy one real
API/admin context below `/module-target`. Vendor webapps, Basic auth, Jolokia
policy and management implementations remain genuine. Public fixture credentials
are admin:admin and user:user. A digest-pinned genuine Apache HTTP server supplies
an unrelated product; target ports publish randomly on 127.0.0.1.

The native gate uses vendor OpenWire decoding/JMS, independent curl and the JDK
HTTP client. Exact product/version/broker/JVM identity, credentials and Origin
policy are verified. The genuine JMX operation fetches static proof XML; only the
broker executes ProcessBuilder. Owner and the proof shell's parent PID must match
the broker JVM. Fixed releases must refuse vm before XML/proof creation. Both
admin and user roles, twelve JMS round trips/removals, three actual TCP bridges,
and exact connector/tmp restoration are exercised. Sealed native preparation
records 111 commands and 50 HTTP observations; bounded bridge polling can vary
command counts across runs.

The 18 Framework examples require product-specific checks, fixed/unrelated/auth
refusals, custom broker discovery, root/prefix paths, explicit broker names,
AutoCheck and handler modes, XML-sensitive commands and invalid CDATA, accepted
user credentials, real Bash/Meterpreter sessions and repeated cleanup. An existing
TCP bridge must survive or the module must safely refuse; connector names alone
cannot establish preservation. Positive outcomes reject failure and ambiguous
error banners. Session files require actual ownership proofs. FETCH_DELETE uses
a real ten-second deadline covering the emitted maximum seven-second delay;
final HTTP listeners must genuinely refuse connections.

Assertions precede fixture restoration. After a failed state assertion, only the
isolated test's known NC connector/proof can be removed to prepare another case;
this cannot turn a failure into a pass. Fetch artifacts are never operator-deleted.
The module refuses a pre-existing NC before creating its callback service or
changing target state. It owns cleanup only after a genuine JSON200/NC acceptance
receipt following that absent preflight. A missing/error/malformed receipt leaves
execution and residual NC state uncertain: the module warns and requires manual
inspection, without deleting a connector by assumption. These uncertainty and
cleanup-error branches have focused derived regressions; the successful live
session paths all have positive native API receipts.

HTTP traces, independent state reads, vendor logs and frozen hashes retain setup
and module failure distinctions. Human module Scenarios remain unchanged.

Windows, TLS, other architectures, ActiveMQ 6.x and alternate delivery commands
are unqualified. OpenWire, legacy fileserver/JSP, source-disclosure and Windows
traversal modules each have separate vulnerability/runtime requirements.
