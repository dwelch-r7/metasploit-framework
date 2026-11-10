# Genuine Gitea repository execution targets

Run both independent profiles with the repository Ruby and installed bundle:

```sh
bundle exec ruby tools/dev/run_module_target_tests.rb gitea_hooks gitea_fetch
```

The [target runner guide](../README.md) describes isolated configuration,
current-input hashes, exact example counts, retained raw artifacts and teardown.
The profiles use the unchanged public Framework check/exploit entry points.
All credentials here are disposable public fixtures; callbacks stay on their
fresh Docker network. No host socket is mounted.

## Targets and independent controls

Digest-pinned vendor Gitea images provide genuine 1.12.6, 1.16.6 and 1.16.7
applications, SQLite databases, Git 2.24.3/2.30.3, and the actual `git` process
identity (UID/GID 1000). Native `gitea migrate` and version-specific admin CLI
commands create the schema and accounts. An Apache reverse proxy really strips
`/gitea/`; changing ROOT_URL alone does not implement that routing.

The [1.13.0 release notes](https://blog.gitea.com/release-of-1.13.0/) explain that
custom hooks became disabled by default. Enabled targets explicitly set
DISABLE_GIT_HOOKS=false; `locked` sets true. A valid ordinary account alone is
insufficient: the native API grants and revokes its specific hook permission
while independently checking it remains nonadministrative. The hook check only
detects a version and warns about the default, so its Appears result is not
permission validation. Gitea 1.16.7 with explicitly enabled hooks remains an
intentional positive hook target.

The [1.16.7 release notes](https://blog.gitea.com/release-of-1.16.7/) and
[security patch](https://github.com/go-gitea/gitea/commit/85e5ac453ba3318e92a493898da887bfa6f165e4)
identify the migration Git-fetch boundary. Native migration controls compare
1.16.6 and 1.16.7 using the same Git version, prove benign clone commit equality,
and independently distinguish harmless malicious-ref command execution from
the fixed invalid-refspec rejection. The blocked profile also refuses local
migration sources. The Python migration service represents the attacker API;
the vulnerable target remains the unmodified vendor application.

Native probes use real REST authentication and cookie/form flows before
Framework runs. They verify exact hook script/committed bytes, a fresh target
marker owned by `git`, repository restoration, valid/invalid accounts and policy
refusals. Cookie-only REST authentication returns 401 on these releases; web
cookie identity is proved against the actual create-repository form instead.
Disabled web hook pages return 404 while the REST hook endpoint returns 403.
Web migration returns 302 before its background task finishes; the real curl
client's bounded retry waits for the migrated master branch before inspection.
Native task/page observations and exact commit checks accompany that gate.

## Automated scope

`gitea_hooks` has fourteen cases covering legacy/current explicitly enabled
hooks, a real prefix, the specifically granted ordinary role, default Linux
bourne delivery with x64 Meterpreter, a Unix Bash shell, missing/unrelated
applications and denied credentials/policy. `gitea_fetch` has fourteen cases
covering authenticated affected/fixed discovery, ordinary-user commands, root
and prefix paths, Bash sessions, Linux curl/wget stagers, fixed-source forced
delivery (with a native invalid-refspec log containing its exact fresh command),
blocked local migrations and invalid authentication with AutoCheck
disabled. Every execution/refusal path runs twice; check-only examples are
bounded discovery assertions.

A session must write a fresh file and its native process must belong to UID
1000. Explicit remote shutdown must remove the observed PID before fallback
session/job cleanup. Per-run assertions require original repository and `/tmp`
inventories after removing only the explicitly declared proof. A failed run's
remaining new repositories are copied before documented operator API removal;
that recovery does not turn the failed assertion into success.

The attacker HTTP service may use Framework's pooled listener. Cleanup requires
no owned resources and actual resource 404 (or connection refusal), plus absent
reverse callback listeners. It does not infer pooled listener closure from an
empty job list. Complete containers/networks/data volumes are removed at the end
of each profile and their identities remain in runner evidence.

These profiles do not qualify Windows, x86/ARM payloads, arbitrary Gitea releases,
external migrations, TLS/proxy combinations, every command-stager flavor or
every authentication provider. Native success does not establish module success;
inspect the exact first baseline and current-input evidence before classifying
any module failure. Human Scenarios in module documentation remain unchanged.

## Console fixture controls

Use the existing header-only HTTP tracing option: a real Gitea license selector
contains `CAL-1.0-Combined-Work-Exception`, which otherwise collides with the
common console helper's error detection. Full initial bodies remain diagnostic
evidence, while the independent native controls retain complete response bytes.
The shared helper remains unchanged. Fetch generic commands retain the module's
ordinary handler-enabled lifecycle and thirty-second WfsDelay, so the queued
Gitea migration can use its attacker resources before cleanup. HandlerNone does
not open a callback listener. Session cases use a ten-second reverse-session
wait. All local state gates retain fifteen-second wall-clock bounds and both
profiles retain the runner's existing ten-minute limit.
