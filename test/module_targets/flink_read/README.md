# Native Apache Flink module targets

These isolated Linux targets cover
`auxiliary/scanner/http/apache_flink_jobmanager_traversal` and
`exploit/multi/http/apache_flink_jar_upload_exec` through the existing module-target
runner. Both profiles use authentic upstream Flink 1.11.2 and 1.11.3 images,
pinned to amd64 image manifests, with their original Java 8 runtimes. The
[Apache advisory](https://www.openwall.com/lists/oss-security/2021/01/05/2)
identifies 1.11.0–1.11.2 as affected by CVE-2020-17519 and 1.11.3 as fixed.
The fixed file-read release still deliberately supports submitting Java jobs;
this lab does not describe JAR submission as fixed by that release.

Run from the repository root:

```sh
bundle exec ruby tools/dev/run_module_target_tests.rb flink_read flink_exec
```

The runner creates fresh Compose projects, assigns only random loopback host
ports and writes raw console, REST, native command and teardown evidence below
`tmp/module-target-tests/`. It removes its containers, networks and volumes.
There is no host engine socket, host network or PID namespace, external cluster,
or host configuration change. The mounted lab files are read-only. The
`start.sh` wrapper creates public artificial fixtures before the original vendor
entrypoint drops the JobManager to the `flink` account (UID 9999). Containers have
explicit memory limits; the upstream JobManager requires a valid process budget,
so it uses 1024 MiB rather than an invalid 512 MiB configuration. Each manager
uses Docker init to reap exited orphan JVM children. The genuine default Java
payload spawns subprocesses; running the vendor JVM directly as container PID 1
otherwise retains exited zombie children even after their descriptors and files
are gone. The test still requires exact Java process restoration.

Two real JobManager/TaskManager pairs provide the vulnerable and patched
versions. Another genuine 1.11.2 JobManager has `web.submit.enable: false`.
Apache httpd provides actual Basic authentication and forwards `/flink/` to the
vulnerable service without decoding encoded traversal paths. The public lab
credentials are `module-test-user` / `module-test-password`. An unrelated real
Apache service supplies the negative HTTP control.

Before module assertions, the independent Python standard-library client checks
vendor CLI/REST versions, Java runtime, the actual server UID, native read access
and denial, exact public/nested/empty bytes, patched and shallow traversal
rejection, and accepted/rejected proxy credentials. The execution profile also
uploads Flink's own bundled WordCount JAR, runs it twice per native route,
requires six real jobs to finish, verifies exact worker output and owner, and
removes each uploaded JAR and result before the module begins. A disabled JAR
endpoint returns HTTP 404 after the server has already staged multipart bytes.
The native control verifies their exact vendor JAR bytes and owner, then restores
that request staging through explicitly recorded operator cleanup. These controls
use the documented [Flink 1.11 REST API](https://nightlies.apache.org/flink/flink-docs-release-1.11/monitoring/rest_api.html).

The read profile has 15 examples, each repeating its operation. It covers actual
version classification, root and authenticated subpath access, exact loot bytes
including an encoded nested filename, rejected/absent authentication, empty,
missing and protected files, insufficient depth, patched traversal, missing base
paths and an unrelated server. Empty readable files are recorded as genuine
HTTP 200 with zero bytes; the existing module emits no successful loot for them.

The execution profile has nine examples. Three exercise staged Java Meterpreter
with its unchanged default `Spawn=2` on both versions and the authenticated
subpath; another uses the inline Java command shell. Each opens and uses two
sessions, verifies the real target file/owner, observes actual JVM processes and
requires uploaded JARs, spawned processes and added temporary files to disappear.
The default Meterpreter cases require an additional live Java process, so a
configured option alone cannot stand in for working subprocess execution.
Five repeated negatives cover disabled submission, absent/rejected credentials,
a missing path and the unrelated server. Disabled submission must refuse
execution and create no session; it can still store the request JAR in Flink
staging before returning 404. The test captures that actual archive, checks its
reported size, valid ZIP CRCs, payload class/manifest/configuration and `flink`
ownership, then explicitly removes its file and new empty staging directories.
This operator restoration is separate from automatic module JAR cleanup. The
other negatives must preserve exact state. Positive output rejects failure
banners and unknown datastore option warnings. Existing jobs must retain their state; the payload entrypoint itself
need not submit a Flink dataflow job. Operator-created proof files are explicitly
removed separately from the module's JAR cleanup.

Windows, other Flink/Java versions, TLS/client-certificate authentication,
non-TCP Java handlers and optional payload modes are outside this profile.
These targets do not establish Windows compatibility or qualify an external
Java 17 payload implementation. Keep any failing run unqualified until its
native controls, exact failure and cleanup have been reviewed.
