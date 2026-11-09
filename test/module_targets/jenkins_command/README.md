# Jenkins anonymous command scanner

Run the isolated profile from the repository root:

```sh
bundle exec ruby tools/dev/run_module_target_tests.rb jenkins_command
```

This family exercises
[`auxiliary/scanner/http/jenkins_command`](../../../modules/auxiliary/scanner/http/jenkins_command.rb).
It extends the digest-pinned official Jenkins2.442/JDK17 targets in
the [shared Jenkins lab](../jenkins/README.md): one open controller, one secured
controller, and unrelated actual Apache HTTP. CSRF stays enabled. Controllers
run as `jenkins`, have no executors/agents/jobs/plugins, use ephemeral homes, and
publish only random loopback HTTP ports. No host Jenkins state is mounted.

Native controls verify actual WAR versions, anonymous route permissions, the
controller account, successful process execution and fresh target-file owner
proof. A matching native CSRF crumb succeeds with its session cookie and fails
without it. Missing executables and unrelated HTTP are independent negatives.
Native commands and HTTP responses are retained with each run.

The seven functional cases cover repeated account output, repeated file creation
with actual owner proof, literal quote/backslash/ampersand/marker output,
literal HTML entities, missing executables, secured access and unrelated HTTP.
The test explicitly removes its own created file after each execution. This is
operator cleanup, not a claim that the module cleans up arbitrary user commands.

Linux retains the module's Java/Groovy `String.execute` tokenization. These cases
use direct executables; they do not qualify shell pipelines or quoted argument
grouping. Process execution keeps the existing one-second bound, followed by
bounded output collection. The result envelope separates command data from
Jenkins HTML, stderr and process-launch failures.

Inspect exact example counts, actual assertions, input hashes and owned teardown
before claiming qualification. Native startup or preflight alone is insufficient.
Windows execution, older Jenkins/Groovy, TLS, reverse proxies, other contexts,
authenticated execution and database persistence remain unqualified. Derived
unit cases and genuine additional producer captures do not add functional cases.
No human module Scenarios are invented. See the [shared guide](../README.md)
for runtime evidence and cleanup rules.
