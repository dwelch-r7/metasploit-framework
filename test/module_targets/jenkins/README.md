# Jenkins target qualification

Run from the repository root:

```sh
bundle exec ruby tools/dev/run_module_target_tests.rb jenkins
```

This profile is under qualification; a definition or passing native preflight
does not count as a passing module family. Inspect the retained result and input
hashes before claiming coverage.

Digest-pinned official Jenkins images provide weekly 2.441/2.442 and LTS
2.426.2/2.426.3 vulnerable/fixed pairs for
[CVE-2024-23897](https://www.jenkins.io/security/advisory/2024-01-24/).
A fifth controller has open script-console access. Each controller uses a
256-MiB Java heap, the real `/jenkins/` context, no jobs/executors/agents/plugins,
and an image-local home volume removed at teardown. Only random loopback HTTP
ports are published. No host Jenkins home, credentials, socket or network is used.

Secured controllers use public account `module_target` / `module-target-password`
and fixture API token `1100000000000000000000000000000000`. CSRF protection stays
enabled. These credentials belong only to the intentionally weak owned lab.

The official CLI is downloaded from each controller into a separate native
client container which has none of the controller fixture files. Independent
controls read actual server-side file bytes, demonstrate the affected/fixed CLI
behavior, distinguish missing/unreadable files, and validate real Groovy access
with password, token or anonymous permissions. HTTP controls validate the
authentication boundary separately. Native source, commands, responses and
WAR/client digests are retained.

Functional cases exercise file-read checks and loot, single/multiple lines,
Unicode and long paths, missing/empty/unreadable files, fixed versions with and
without forcing, login negatives, enumeration, script-console password/token/open
modes, command and x86/x64 Bourne delivery, and real command-shell/Meterpreter
sessions. State-changing paths repeat with native command proof. Non-session
deliveries use explicit operator removal of newly created target files; this is
not a claim of module cleanup. Session cases also check automatic stager cleanup.
The owned lab is removed even when assertions fail.

Windows targets, other Jenkins releases, root context, TLS, reverse proxies,
restricted authenticated roles, non-Bourne stagers, external identity providers,
arbitrary encodings/locales and database reporting remain unqualified. Existing
human-written module Scenarios are preserved. See the [shared guide](../README.md)
for evidence and cleanup rules.
