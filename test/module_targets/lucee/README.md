# Lucee image-write native acceptance target

```sh
MODULE_TARGET_NAMESPACE=lucee-local bundle exec ruby tools/dev/run_guarded_module_target_tests.rb lucee
```

The recipe pins the official Linux amd64 Lucee **5.3.7.43** image by digest.
The real server uses Tomcat on port 8888, Java 11.0.8 and UID 0. The unchanged
vendor JAR is fingerprinted before and after tests. A separate application
template supplies native CFML controls without modifying vendor admin code.
The application and content-server ports publish only on loopback.

Independent Bash and real CFML controls prove exact ASCII, quoted, Unicode and
multiline command bytes before owner execution. A native request to the genuine
image-write endpoint separately proves the physical CFML file, its implicit
trailing newline and real interpretation through the normal Lucee mapping.
Each proof and temporary directory is removed before reuse.

The actual module check and Unix command target use `cmd/unix/generic` with
the normal `AllowNoCleanup=true` option required for a sessionless command.
Each owner case repeats on the same selected console object, with AutoCheck
enabled first and disabled on repeat. Real method/request events, physical
command output files and the uploaded CFML source establish execution rather
than an HTTP status or success message. With no session, fixture cleanup removes
the module's recorded CFML artifacts; this does not qualify FileDropper session
cleanup. Linux dropper targets, sessions and other versions remain unqualified.

Run serially through the guarded runner with an explicit namespace. Only one
application container runs: 1 CPU, 768 MiB memory/equal swap and 128 PIDs. Ensure
cleanup removes finished containers and ephemeral networks immediately, including
after failures. Automated captures do not supply human module Scenarios.
