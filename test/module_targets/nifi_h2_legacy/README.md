# Genuine NiFi H2 legacy target

Run `bundle exec ruby tools/dev/run_module_target_tests.rb nifi_h2_legacy`.

This isolated release profile reuses the pinned stock Apache image and actual
public fixture account from `../nifi`. A separate native HTTP client verifies
version, login policy, authenticated and refused requests, the actual H2 JAR
checksum/version through its vendor CLI, and the file-URL trigger before the
module runs. The fixed release must reject the JDBC scheme without executing.
A stopped GetHTTP component authenticates to real Apache before and after.

The corpus exercises repeated commands and real reverse shells on affected
releases, authentication refusals and the fixed-version check/forced attempt.
The legacy generic command and current affected release's shell case retain
ordinary DELAY=30, whose cleanup waits twice. Native legacy controls recorded
zero tasks with a two-second pre-stop wait and actual execution at thirty
seconds. Other cases use public DELAY=2 with their recorded handler waits;
that shorter delay is not qualified for legacy generic commands or every
runtime. The local command read bound includes the two declared cleanup waits;
shared limits are unchanged.

The module declares ARTIFACTS_ON_DISK. New random file-database paths are captured
and hashed after graph cleanup, then explicitly removed by the native operator
fixture. This is not module file cleanup. UUID graph restoration after an error
is likewise labelled operator restoration and only accepts actual emitted IDs.
No broad target deletion or response simulation occurs. Unix command payloads
and these Linux releases are the scope; Windows and other NiFi/H2 combinations
remain unqualified. Self-signed local TLS has verification disabled.
