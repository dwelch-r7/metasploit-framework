# Langflow validation authentication boundary

These profiles use official Linux amd64 images pinned by digest. Langflow 1.2.0
runs with login enabled to exercise CVE-2025-3248. The documented 1.3.2 release
runs with automatic login enabled and disabled to cover the module's later
configuration path and the authentication boundary.

```sh
DOCKER_CONTEXT=default BUILDX_BUILDER=default bundle exec ruby tools/dev/run_guarded_module_target_tests.rb langflow_validation_bypass langflow_validation_autologin langflow_validation_guarded
```

Independent native controls verify twenty installed source hashes per release,
effective backend settings and builtin names, actual version responses, valid
login and the complete flow registry. They distinguish the unguarded 1.2.0
validation route from guarded API routes: validation accepts both anonymous
requests and invalid bearer tokens while other protected routes reject them.
After the authentication fix, invalid bearer tokens are rejected; disabling
automatic login also denies anonymous validation. Authenticated native controls
still execute, which distinguishes protection from a broken validator.

Repeated default-argument and decorator canaries require exact UID 1000/GID 0
file writes. Native files are removed and complete before/after state must match.
No provider or model is required. Version 1.2.0 has no lazy-loading setting; its
recipe uses its normal loading behavior. Version 1.3.2 explicitly retains eager
loading. Application endpoints and implementation remain unchanged.

The two positive profiles cover repeated check, exact command writes, Python
shell and staged Meterpreter with both fork settings, AutoCheck on/off and
refused ports. The guarded profile covers Safe, normal AutoCheck abort, forced
and disabled-AutoCheck denials, absent marker files and handlers closing without
sessions. Each case repeats on the same selected owner. Sessions require real
readiness, remote identity/file proof, database provenance, live backend health,
closure and complete process restoration.

This module exposes no TARGETURI option. The acceptance helper omits that
unsupported default and tests the public root-path interface. Other owners keep
their existing defaults. URL-prefix support is outside this module's current
public interface.

Only three containers run at once: target 3,072 MiB/one CPU, Framework
768 MiB/one CPU and database 128 MiB/0.2 CPU. Swap equals memory and published
ports bind to localhost. The shared guarded runner serializes worktrees and
removes each project before the next profile starts.

Scope is these two one-worker Linux images, the three authentication states and
the exercised payload families. Other releases, platforms, replicas, TLS,
providers and stageless payloads need separate evidence. The broader campaign
remains incomplete.
