# Commons Text native-gated module tests

These opt-in profiles run the referenced Spring Boot proof application at
[source commit 288959e](https://github.com/karthikuj/cve-2022-42889-text4shell-docker/tree/288959eddad312218ec31c7bc06cf2622b26e91e),
with pinned archive and base-image digests. The original controller really calls
`StringSubstitutor.createInterpolator().replace(search)`. It is not an HTTP
response emulator. [Apache's advisory](https://commons.apache.org/proper/commons-text/security.html)
explains that vulnerable library versions alone do not establish application
exposure: untrusted input must reach that interpolator.

```sh
MODULE_TARGET_NAMESPACE=text4shell-local bundle exec ruby tools/dev/run_guarded_module_target_tests.rb text4shell text4shell_post text4shell_fixed
```

Profiles run serially, one capped service at a time: **384 MiB / 0.7 CPU**, UID
1000, loopback-only dynamic port, bounded temporary files and immediate teardown.
Use an explicit task namespace and the guarded shared lock. No host Docker socket,
privileged service, persistent volume or extra daemon is used.

| Profile | Library | HTTP controller |
| --- | --- | --- |
| `text4shell` | 1.8 | Original GET-only source |
| `text4shell_post` | 1.8 | Explicit derivative: mapping accepts GET and POST |
| `text4shell_fixed` | 1.10.0 | Original GET-only source |

The POST derivative changes only the Spring mapping annotation. It exercises
the module's form-body path without changing interpolation or command handling.
The original and active controller hashes are checked independently. The fixed
profile changes the library version, with the same controller and Java runtime.
All profiles include a separate native CLI class built with the application's
real dependencies; the HTTP handler does not call that class.

Each profile first checks the actual Java/library versions, Nashorn availability,
controller source hashes, literal HTTP bytes, method support and UID. The exact
plain and quoted/Unicode/CRLF commands must work through direct shell and direct
Nashorn execution. The real CLI interpolator and real HTTP route must then either
execute those same commands (1.8) or block them (1.10.0). Files are independently
read for exact bytes and owning UID, then removed. A foreign file and application
artifacts must remain unchanged.

Only after those gates pass do actual owner checks and Unix Command target runs
execute. Tests cover repeated checks on one selection, both command bodies on
one selection, GET versus POST parameter placement, an unconsumed parameter,
the original controller's 405 response, and refused-port check/exploit handling.
The module does not prepend AutoCheck; tests record that fact and do not invent
automatic refusal. Fixed-version calls must create no command proof even when
the module accepts an HTTP 200 response. Passive traces retain actual owner and
HTTP calls, return values and failures without replacing production methods.

The Java in-memory default target, Java sessions, Linux dropper and Windows paths
remain separate qualification work. Registration is not proof of pass; use the
dated verification report for observed results and limitations. Human-written
module Scenarios are preserved.
