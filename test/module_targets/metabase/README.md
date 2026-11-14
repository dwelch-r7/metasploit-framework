# Metabase setup-token execution targets

The labs run pinned official images with their original application startup. Each installed JAR matches its publisher's GitHub release SHA-256; [vendor.json](vendor.json) records the image and JAR identities. Application data and Framework reports use separate PostgreSQL databases and roles. No external account, provider or license key is configured.

Start with the modern affected/fixed pair:

```sh
DOCKER_CONTEXT=default BUILDX_BUILDER=default bundle exec ruby tools/dev/run_guarded_module_target_tests.rb metabase metabase_fixed
```

Select additional release boundaries and setup states explicitly. The launcher runs them serially, with teardown before the next startup.

| Profile | Version | State | Expected check | Cases | Execution contract |
| --- | --- | --- | --- | ---: | --- |
| `metabase` | 0.46.6 | Configured | Appears | 15 | Command and Bash session |
| `metabase_fixed` | 0.46.6.1 | Configured | Safe | 8 | Fixed backend rejection |
| `metabase_legacy_044` | 0.44.4 | Configured | Appears | 10 | Command and Bash session |
| `metabase_fixed_044` | 0.44.7.1 | Configured | Safe | 8 | Fixed backend rejection |
| `metabase_initial_042` | 0.42.1 | Fresh | Appears | 10 | Command and Bash session |
| `metabase_configured_042` | 0.42.1 | Configured | Appears | 8 | Missing-token rejection |
| `metabase_legacy_043` | 0.43.7.1 | Configured | Appears | 10 | Command and Bash session |
| `metabase_fixed_043` | 0.43.7.2 | Configured | Safe | 8 | Fixed backend rejection |
| `metabase_legacy_045` | 0.45.4 | Configured | Appears | 10 | Command and Bash session |
| `metabase_fixed_045` | 0.45.4.1 | Configured | Safe | 8 | Fixed backend rejection |
| `metabase_enterprise` | 1.46.6 | Configured | Appears | 10 | Command and Bash session |
| `metabase_enterprise_fixed` | 1.46.6.1 | Configured | Safe | 8 | Fixed backend rejection |

## Controls and coverage

Independent native API calls verify the version, normal setup and authenticated administrator session where configured. A genuine H2 connection-validation probe must produce exact UTF-8 file bytes as UID 2000 on affected states. Wrong-token and protected-state controls must leave no file; HTTP 400 alone establishes neither execution nor protection. Metabase 0.42.1 clears its token during setup. Newer fixed versions retain a visible token while rejecting malicious connection options or initialized setup operations.

Actual public check/run calls repeat from the same console configuration with Framework's normal execution replicants. They cover ASCII/UTF-8 commands, genuine JSON health and missing routes, refused ports, AutoCheck disabled and ForceExploit enabled. The main profile covers all three command-length residues needed by the base64 padding logic. Configured 0.42.1 retains a passive Appears version check but must reject exploitation when both token locations are empty, without a validation POST.

Affected profiles open, use and close real Bash sessions. The main profile also exercises netcat and verifies removal of its randomized FIFO. Native file bytes, UID, PID ancestry and real Framework session/database rows must agree. Remote shell exit is verified before Framework transport closure, followed by closed_at, process removal and idle jobs/sessions. Test cleanup removes the operator-requested marker files.

The declared generic Unix target rejects Linux-specific curl/wget Meterpreter fetch payloads before any owner request; this matrix does not qualify Meterpreter delivery. Focused contract specs cover malformed bootstraps, connection failures, version boundaries and same-instance reuse with explicit HTTP doubles.

## Isolation and cleanup

Each functional profile uses three containers on an internal network with no host ports. Limits are:

| Service | CPU | Memory | PIDs |
| --- | ---: | ---: | ---: |
| Target | 1.5 | 1536 MiB | 256 |
| PostgreSQL | 0.5 | 256 MiB | 64 |
| Framework | 1 | 768 MiB | 256 |

The JVM heap is capped at 768 MiB with two active processors. PostgreSQL uses a bounded tmpfs. The shared launcher refuses an existing container inventory and checks resolved service counts; its global hard limit is five. Keep this family serial.

Records in core_user, setting and metabase_database, plus application process identities, must return to baseline after each case. Final checks verify JAR identity and zero OOM/PID-limit events. The runner captures logs, health, image IDs and resource identifiers before `compose down --volumes --remove-orphans`; independent exact-ID, project-label and global inventory queries verify removal.

## Provenance and limits

The [vendor advisory](https://www.metabase.com/blog/vulnerability-advisory) supplies OSS fixes 0.43.7.2, 0.44.7.1, 0.45.4.1 and 0.46.6.1, with corresponding Enterprise 1.x releases. Fixed shipped JARs omit Clojure sources present in affected JARs, and the reviewed 0.44/0.46 public hotfix tags do not expose the complete installed security patch. These labs establish binary provenance through release checksums and native behavior; they do not claim fixed installed code equals public-tag source.

Coverage is limited to the pinned Linux amd64 images and listed states. Enterprise profiles exercise public core setup/validation without paid features. Other releases, databases, licensed features, transports and session families remain outside the matrix. The [module guide](../../../documentation/modules/exploit/linux/http/metabase_setup_token_rce.md) retains the original human-written Scenarios.
