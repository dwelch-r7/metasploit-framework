# Jetty WEB-INF file disclosure

From the repository root, run profiles serially with the shared guard:

```sh
bundle exec ruby tools/dev/run_guarded_module_target_tests.rb jetty_webinf_9438 jetty_webinf_9443 jetty_webinf_1005 jetty_webinf_1006 jetty_webinf_1105 jetty_webinf_1106 jetty_webinf_unrelated
```

Each profile has only its own target and Framework: **two containers,
1,024 MiB/1.25 CPUs**. The target has 256 MiB/0.25 CPU/128 PIDs and Framework
768 MiB/one CPU/256 PIDs, with swap equal to RAM, no privileged mode, one project
bridge and a random loopback HTTP port. The guard refuses unrelated containers
and overlapping campaign invocations. Every profile is torn down before the next.
The separate [unrelated Apache control](../jetty_webinf_unrelated/README.md)
also uses two containers, capped at 864 MiB/1.1 CPUs. Normal metadata reuse within
one invocation is allowed; no first console seed
is supplied manually.

The genuine official Jetty images are pinned to verified Linux amd64 manifests
in `profiles.json`. Their standard entrypoint, server classes, web application
modules and URI compliance remain unchanged. The Dockerfile adds ordinary
`ROOT/WEB-INF` files and limits Java heap/thread resources. The original Jetty
distribution, rather than a response simulator, handles every request.

Jetty's advisories identify the
[9.4.37/9.4.38 encoded-dot flaw](https://github.com/jetty/jetty.project/security/advisories/GHSA-v7ff-8wcx-gmc5)
and [the later encoded-URI flaw and branch fixes](https://github.com/jetty/jetty.project/security/advisories/GHSA-vjv5-gp2w-65vm).
The target matrix exercises both CVE options on affected and fixed 9.x, 10.x and
11.x releases. No compliance workaround is configured to make a fixed version
vulnerable.

Before owning calls, the independent Python standard-library client verifies the
real root document and Server version, unprivileged server process identity,
protected ordinary paths, both actual encoded-URI behaviors, missing resources,
and a refused TCP port. Exact HTTP status/headers/body bytes and direct on-disk
file bytes are retained. Short, empty, Unicode, binary, multi-buffer and nested
files must agree with actual target files on affected releases. Fixed releases
must reject the same requests. These controls run again after module cases;
file hashes and the actual Java PID/start time must remain unchanged.

Functional cases call the public module through msfconsole. They check both CVE
selections twice, repeat default-file reads/refusals, compare exact native loot
bytes, reject missing/error-page loot, exercise AutoCheck disabled, and handle a
native-verified refused connection. Native setup failure is not a module verdict.
Non-UTF8 console output is preserved as Base64 in the owning record without
replacing the console or changing module behavior.

Registration is not qualification. Consult actual result counts, native controls,
current source hashes and a dated verification report. Custom applications,
authentication, HTTPS, nondefault compliance, other releases and files outside
the deployed application's WEB-INF tree remain outside these profiles. Existing
human module Scenarios are preserved.
