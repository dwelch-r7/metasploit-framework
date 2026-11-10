# Genuine ActiveMQ OpenWire qualification

Run `bundle exec ruby tools/dev/run_module_target_tests.rb activemq_openwire`
from the Framework root. This family builds genuine Apache 5.18.2 and 5.18.3
archives, checks their publisher SHA512 digests, and uses a digest-pinned official
Temurin 17 amd64 JDK. The targets run as `activemq`. Only Jetty's loopback bind
is changed to permit isolated-container access; JVM memory/processor limits are
explicit. Target ports publish randomly on 127.0.0.1.

Apache identifies 5.18.2 as affected by CVE-2023-46604 and 5.18.3 as fixed.
The official source adds a Throwable type check before reflective construction.
Sources, actual runtime identity, OpenWire frames and native observations belong
to each qualification report rather than an inferred image-tag version.

The independent native gate uses the vendor OpenWire decoder and genuine JMS
producer/consumer APIs. An actual broker receives an independently encoded
ExceptionResponse and fetches static proof XML from a native Java HTTP listener.
That listener only serves bytes; it never executes commands or impersonates the
broker. Proof parent PID must match the real broker JVM, owner must be activemq,
and repeated JMS round trips and destination removal must work before/after.
The patched broker must fetch no XML and create no proof. Native proof files
and temporary-directory contents are restored across repeats.

Stock Jolokia policy rejects requests without an Origin header. Native API calls
and readiness checks supply a valid Origin, inspect JSON status, and independently
verify the actual broker version. This is separate from the OpenWire attack.
Default HTTP fixture credentials are the vendor's public `admin:admin`; the
OpenWire transport uses the vendor's default unauthenticated configuration.

The 14 examples cover repeated affected/fixed checks, AutoCheck refusals,
Linux fetch-exec and Unix generic commands, root/prefix callback paths and
XML-sensitive text, AutoCheck-disabled initialization, disabled payload handlers,
invalid CDATA rejection, Unix Bash and Linux fetch-shell sessions, and genuine
Linux x64 fetch-Meterpreter sessions with shared/separate HTTP ports.
Positive runs reject failure banners and require independent files, owner and
session proofs. Fetch artifacts must disappear before repeats; operator deletion
cannot hide a failed fetch cleanup. Read-only lifecycle observations copy owned
paths before cleanup and record actual callback/fetch identities and reference
counts afterward. Every former path must genuinely refuse HTTP connections after
the final owner closes, and no HTTP service may remain registered. These checks
use real curl from Linux target containers, avoiding timed-Socket object returns
as a substitute for an HTTP connection.

The dependency list includes the shared HTTP/HTTPS ownership regressions and
their benign capture. They verify that cleanup preserves concurrent normal and
fetch routes until the last owner releases the actual service. The original
49-key qualification against the old shared helper retained empty fetch-owned
listeners and real 404 responses; its raw results remain separate. The expanded
dependency set and stricter final-listener contract record the shared repair
explicitly, without weakening command, session, state or repeated-run assertions.

FETCH_DELETE deliberately emits a randomized three-to-seven-second deletion
delay. Exact temporary-directory restoration uses a real ten-second wall-clock
deadline around the existing expectation-retry helper and returns immediately
when restored. Retry counts are not seconds. The first strict 55-key run's two
artifact observations used ten attempts with 0.1-second sleeps; both exact files
disappeared later without operator deletion. That 14/2 diagnostic is retained
separately. Deadline/elapsed receipts preserve the actual bounded cleanup result.

Windows, other CPU architectures, TLS transports, alternative fetch commands,
other ActiveMQ branches and arbitrary external targets are unqualified. Other
ActiveMQ modules have separate vulnerability/configuration requirements and are
not qualified by this family. Existing human Scenarios remain intact.

Primary references:
- https://activemq.apache.org/security-advisories.data/CVE-2023-46604-announcement.txt
- https://activemq.apache.org/components/classic/download/classic-05-18-02
- https://activemq.apache.org/components/classic/download/classic-05-18-03
