# Lucee fixed-release acceptance target

```sh
MODULE_TARGET_NAMESPACE=lucee-fixed-local bundle exec ruby tools/dev/run_guarded_module_target_tests.rb lucee_fixed
```

The recipe pins official Linux amd64 Lucee **5.3.7.47**, a fixed release in the
[vendor advisory](https://github.com/lucee/Lucee/security/advisories/GHSA-2xvv-723c-8p7r).
The genuine JAR is fingerprinted before and after execution. Native metadata
establishes Java 11.0.9, UID 0 and the real Lucee context and webroot paths.

Independent Bash and CFML controls prove exact ASCII, quoting, Unicode and
multiline command bytes. Before each denied-owner attempt, genuine CFML writes
a physical template into the real context directory, and HTTP interprets it.
After removal, the original check, base-directory and traversal-write requests
all return empty 404 responses and leave the template absent. Vendor code and
HTTP handling are unchanged. A separate mounted application supplies controls.

The real module returns a reason-bearing Safe result. AutoCheck then withholds
two executions on the same selected console object, without entering the
actual exploit body or producing a CFML stub. Sessionless attempts explicitly
set the normal `AllowNoCleanup=true` option; they do not test session cleanup.

Run serially with an explicit namespace. One application container uses 1 CPU,
768 MiB memory/equal swap and 128 PIDs, with port 8888 published on loopback.
Finished and failed stacks are removed immediately, including their ephemeral
networks. Other fixed branches, sessions and dropper targets remain unqualified.
Automated captures do not supply human module Scenarios.
