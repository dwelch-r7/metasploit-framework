# Hadoop YARN execution

This lab runs genuine Apache Hadoop 3.4.2 ResourceManager, NodeManager, NameNode
and DataNode processes from the digest-pinned Apache image plus the signed,
SHA256-pinned CentOS `which` package required by the automatic Bourne stager. The runtime reports
source revision `84e8b89ee2ebe6923691205b9e171badde7a495c`. It uses Hadoop's
vendor environment-to-XML configuration tooling and native DistributedShell
client. No Docker socket, privileged container, external callback or host service
is used. Published ports bind to random host loopback ports. Compose must support
`include` (2.20+) for the session profile. The short `yarn_live` family name keeps
canonical Compose container DNS labels within 63 bytes. Hadoop's native
DataNode hostname-validation check remains enabled.

```sh
bundle exec ruby tools/dev/run_module_target_tests.rb hadoop_yarn yarn_live
```

The two profiles retain sixteen check/command cases and three session cases,
each separately subject to the runner's existing ten-minute bound. Each fresh
cluster first proves one live HDFS DataNode, one RUNNING NodeManager, exact CLI
and API build identity, then two registered DistributedShell jobs with real
worker-created files and `FINISHED`/`SUCCEEDED` results. Independent GNU assembler
and linker controls build and execute source-supplied static x86/x64 ELF programs
on the NodeManager before any Framework delivery. These are target test inputs,
not Framework payloads or project dependencies.

Native REST controls independently write and remove exact fresh marker bytes
twice anonymously and through both the prefix and authenticated gateway routes.
The real Apache gateway proxies `/yarn/` without authentication and `/secured/`
with public fixture Basic credentials `module-test-user:module-test-password`.
Its `/denied/` policy returns 403; absent and wrong credentials return 401;
missing and unrelated Apache paths return 404. These are deployment policies,
not patched Hadoop versions or Kerberos. No secure-mode qualification is claimed.

The owning module reads `TARGETURI` but does not register it. Default-root cases
omit the field. Non-root cases retain and record its console warning and test the
implemented datastore override; this does not establish clean registered-option
validation or advertised base-path support. Any other unknown option fails the
fixture. The existing human module Scenarios remain unchanged.

The module exposes Linux x86/x64 CmdStager delivery. The command profile covers
its automatic stager, printf, curl and wget with exact target bytes; the session
profile uses x86 shell, x64 staged Meterpreter and a wget-delivered x64 shell.
Every positive path runs twice. Command payloads retain Framework's ordinary
handler lifetime so queued HTTP downloads can complete. Session payload options
are distinct: x86 shell `CMD` is the executable pathname `/bin/sh`; exec payload
`CMD` is shell command text; the x64 shell and Meterpreter receive no `CMD`.
A check allocates an application ID; that alone
does not prove successful application submission or command execution. Native
controls prove both separately.

Direct commands are not registered ApplicationMasters. A command may execute
while its YARN application remains ACCEPTED or later fails/retries. The fixture
records actual application/attempt state and explicitly kills only applications
created by that run before shutting down sessions. It records each real remote
session PID, proves that PID was live, and requires it to disappear. It waits for no active
application, allocated container or NodeManager container, captures remaining
new `/tmp` files, and records operator removal of those exact files. The module
does not claim automatic YARN application cleanup. Application history and
native logs remain until the owned cluster is removed; they are not treated as
live state or silently compared to an empty history.

Each run retains native HTTP bodies/headers and vendor command outputs,
per-example console transcripts, application/attempt metadata, copied target
files, current source fingerprints and operator-restoration receipts. Callback
listeners must close. HTTP services may be pooled: the fixture requires empty
owned resources and a real 404 or connection refusal for each actual generated
stager URL, rather than assuming every pooled listener closes.

Native job client waits are 90 seconds (120-second outer command bound), HTTP
requests ten seconds, native command markers thirty seconds, Framework HTTP
requests five seconds, payload session wait fifteen seconds, and the owning
console operation seventy seconds. A lost console stops the family to prevent
later labels from becoming false module verdicts. A runner timeout remains an
unqualified diagnostic, even if earlier cases passed.

This scope does not cover Kerberos, TLS/SPNEGO, HA ResourceManagers, Windows,
other schedulers/releases or all stager flavors. It does not turn anonymous
application-ID allocation into a hard vulnerability check. The original owning
source is frozen for the first complete baseline; failures must be classified
against independent native controls before any source repair.

Primary sources: [Apache image configuration](https://github.com/apache/hadoop/tree/docker-hadoop-3.4.2),
[ResourceManager REST API](https://hadoop.apache.org/docs/r3.4.2/hadoop-yarn/hadoop-yarn-site/ResourceManagerRest.html),
[writing YARN applications](https://hadoop.apache.org/docs/r3.4.2/hadoop-yarn/hadoop-yarn-site/WritingYarnApplications.html),
and [Hadoop secure mode](https://hadoop.apache.org/docs/r3.4.2/hadoop-project-dist/hadoop-common/SecureMode.html).
