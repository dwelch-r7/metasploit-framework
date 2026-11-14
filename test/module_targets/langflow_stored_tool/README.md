# Langflow stored-tool functional targets

Run the digest-pinned official Linux amd64 1.8.4, 1.9.0 and 1.10.0 profiles
sequentially:

```sh
DOCKER_CONTEXT=default BUILDX_BUILDER=default bundle exec ruby tools/dev/run_guarded_module_target_tests.rb langflow_stored_tool_legacy langflow_stored_tool langflow_stored_tool_fixed
```

The affected profiles exercise CVE-2026-10134 version checks, exact credential-created
commands, Python shells and staged Meterpreter with both fork settings. Each path
runs twice, including AutoCheck-disabled execution, invalid credentials, private
and missing UUIDs, refused ports, missing prefixes and credential-to-public mode
transitions. The guarded 1.10.0 profile checks Safe/normal AutoCheck, ForceExploit,
AutoCheck-disabled commands and handlers, and existing public/private flows.
These are bounded representatives, not coverage of every affected version.

`FLOW_UUID` triggers code already stored in an existing public flow. It does not
upload the selected payload. A canary case explicitly requires stored-code
execution and absence of the selected command. Separate session cases prepare
new public flows with matching genuine Framework-generated Python payloads,
then let the owner trigger those stored payloads. This setup is a prerequisite,
not payload delivery by the module. Those fixture flows are removed separately.
Repeated console selection uses Framework executing replicants; the unit suite
separately labels direct same-object cleanup coverage.

Independent native controls verify 43/44/43 installed source hashes, actual
settings, complete finite build events, exact UID 1000/GID 0 canaries and full
flow records. Login is required, eager loading is enabled, and custom components
are permitted where that setting exists. On 1.10.0 the rate limiter remains
enabled with a fixture quota of 100/minute. No endpoints are replaced, and no
model or provider is required. The owner consumes its own public-job events;
the acceptance suite does not drain that queue again.

Langflow 1.10.0 removed the legacy component. Its migration control uses the
unmodified 1.9.0 source in `legacy_component.py`, compiled through the genuine
authenticated component API. Authenticated private builds succeed while the
public route rejects that component type. This is not a claim that 1.10.0 ships
it. `vendor.json` records installed code, source origin and hashes;
`LICENSE.langflow` preserves the upstream MIT license.

Session acceptance requires live remote identity and file proof, correct
Framework/database module and payload provenance, backend health while the
session is open, graceful shutdown, and disappearance of the exact PID/birth
pair. Every case restores jobs, sessions, connections, the process baseline and
complete native flow records; native fixtures are deleted at the end.

Only three capped containers run at once: target 3,072 MiB/one CPU, Framework
768 MiB/one CPU and database 128 MiB/0.2 CPU. Swap equals memory and published ports
bind to localhost. The guarded runner serializes worktrees and removes each
project and its volumes after the profile. Initial failures and untested paths
remain evidence, not passing qualifications.
