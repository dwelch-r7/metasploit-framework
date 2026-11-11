# OneDev file reads

```sh
bundle exec ruby tools/dev/run_guarded_module_target_tests.rb onedev_11_0_8 onedev_11_0_9 onedev_unrelated
```

The genuine vendor images are pinned by platform manifest/config digests in
[profiles.json](profiles.json). The original entrypoint, upgrader and application
handlers are retained. A disposable data volume supplies the vendor-required
install directory, and ordinary read-only fixtures supply text files. No host
Docker socket, executor, CI build or external database is used.

Unattended vendor environment options create a task-only administrator. Native
HTTP clients verify actual version, accepted/rejected authentication, private
project creation, ordinary published-site content, and the real file-read path
with anonymous access enabled and disabled. They compare HTTP bytes to actual
files, including empty, Unicode, large, spaced and error-phrase content. A five
byte binary fixture is generated explicitly as `[0,255,65,66,10]`; no binary
payload is distributed. Missing files, directory redirects, project lookup and
same-namespace refused connections have independent controls.

The native pre/post probes restore anonymous access to disabled and verify stable
project/security/file state, the JVM identity and clean memory/PID counters.
Wordlists are fixed, short repository fixtures. Module calls cover check,
stdout/loot, explicit project/wordlist, AutoCheck-disabled, negative and repeat
paths. Every loot file must match native bytes, and negative paths must create
none. The unrelated profile uses genuine Apache rather than an invented banner.

Each OneDev profile uses two containers capped at 1,536 MiB/1.5 CPUs: target
768 MiB/0.5 CPU/256 tasks and Framework 768 MiB/1 CPU/256 tasks. The vendor JVM
gets a 320 MiB heap and bounded native areas. Only host-loopback HTTP is published.
Profiles run serially; each data volume/network/container is removed afterward.
The unrelated Apache control uses 64 MiB/0.1 CPU/128 tasks, plus the same bounded
Framework container, and verifies genuine HTTP readiness before tests.
Registration does not prove qualification: current passing examples, native
controls, input hashes and independent exact cleanup are required.

The vendor [advisory](https://github.com/theonedev/onedev/security/advisories/GHSA-7wg5-6864-v489)
identifies 11.0.8 as affected and 11.0.9 as fixed. Setup follows the pinned
release's source, including its unattended initialization and wrapper configuration;
current deployment documentation alone does not establish old-release behavior.
