# Genuine OpenTSDB graph targets

Four fresh single-release projects exercise the yrange module on 2.4.0 and 2.4.1,
and the key module on 2.4.1 and source-built 2.5.0-RC1. The latter is an actual
published fixed-source tag; there is no claim of a released 2.4.2 image.

```sh
bundle exec ruby tools/dev/run_module_target_tests.rb opentsdb_yrange opentsdb_yrange_fixed opentsdb_key opentsdb_key_fixed
```

The base is digest-pinned Vulhub OpenTSDB 2.4.0 with its unchanged vendor
entrypoint, HBase 2.4.5, Java 8u302, Gnuplot 5.4.1 and native root UID. A 2.4.1 image
installs the official publisher Debian package with its recorded SHA-256. The
fixed build replaces the complete OpenTSDB runtime/dependencies and genuine GWT
UI from official revision 0f681b7545d9999506900da5f1c4dbe433dbfb43. Its full runtime
JAR hashes are recorded by the builder and checked again live. These are
reproducibility hashes, not a publisher signature claim. No opaque binary is
checked in. Builder system packages and upstream dependency downloads are saved
in image provenance; their mirrors are external build prerequisites.

Each project has only one HBase/OpenTSDB service, a real Apache Basic-auth proxy
at /tsdb/ and an unrelated Apache. Ports publish only on random loopback ports.
Root/root is not an application account: OpenTSDB itself has no authentication
here. module-test-user/module-test-password is an explicit Apache fixture.
The runner adds its canonical Framework container; project-scoped teardown
removes containers/networks/volumes and retains logs, image IDs and input hashes.
Cached images remain. No external host or existing service is tested.

Independent stdlib Python controls check CLI/API revisions, all live publisher
JARs, process/UID, six real time-series points, every 3 metric × 35 aggregator choice,
a genuine PNG graph, credentials (401/200), missing routes (404) and unrelated content.
Transparent NASM source builds no-op x86/x64 ELF files in the canonical Framework
image and verifies actual target execution/exit 42 before module payload tests.
Python payloads are outside this corpus: the target has no Python prerequisite.
Native exact quote/backslash/plus/chmod-string controls precede command tests;
fixed releases must reject the same real graph injection without a proof file.

The family-local console formatter proves actual Rex lexer round trips; an
observational prepend records executing-replicant CMD and execute_command bytes,
without regenerating payloads or changing requests. Generic command vectors,
base/prefix checks, auth/missing/unrelated/closed cases, AutoCheck, actual sessions
and command-stager/Fetch delivery families repeat. A session must both emit its
opened banner and appear in the registry, execute a target UID/file/PID proof,
then close with that remote PID absent. Public compatibility remains enforced.

Top-level temporary files and the genuine Java daemon processes are recorded
before/after each case. Generic proof files are explicit operator cleanup. Fetch
leaves its downloaded file by default: the default-curl case records its hash
before operator removal; the wget case requests FETCH_DELETE and verifies its
ordinary removal. Dropper cases require their temporary files to disappear before
passing. Failures retain explicit operator restoration separately from success.
Legitimate graph caches and HBase data are disposable project state, rather than
claims of automatic module cleanup. Callback/HTTP listeners must disappear.

Other OpenTSDB releases/configurations, HBase backends, TLS, other CPU/OS targets,
empty metric/aggregator stores, arbitrary Gnuplot syntax and payload families are
unqualified. Successful native controls establish the fixture before a module
failure is attributed. Existing module-document Scenarios remain human-written.
