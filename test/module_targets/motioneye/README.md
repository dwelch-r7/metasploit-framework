# Native motionEye acceptance targets

These profiles exercise the actual authenticated command-execution owner against
upstream motionEye images and the installed Motion daemon. Registration is not a
passing result. See the [verification record](../VERIFICATION-20261119-motioneye.md)
for observed qualification.

| Profile | motionEye | Administrator password | Expected injection behavior |
| --- | --- | --- | --- |
| `motioneye` | 0.43.1b4 | Blank | Command execution |
| `motioneye_password` | 0.43.1b4 | `module-target-admin` | Command execution |
| `motioneye_fixed` | 0.43.1 | `module-target-admin` | Rejected configuration |
| `motioneye_fixed_blank` | 0.43.1 | Blank | Rejected configuration |

Use the repository's existing Ruby bundle, Docker Compose and NASM:

```sh
MODULE_TARGET_NAMESPACE=motioneye-dev \
  bundle exec ruby tools/dev/run_guarded_module_target_tests.rb \
  motioneye motioneye_password motioneye_fixed motioneye_fixed_blank
```

Select one profile for a shorter run. The guarded runner holds the common
worktree lock and runs stacks serially. Do not add an outer lock around it.
Each stack has the app and a Framework reporting database. The app is capped at
0.75 CPU, 512 MiB and 128 PIDs; the database retains its shared smaller limits.
Only random loopback ports are published. Finished stacks and volumes are
removed immediately, including after failed tests. Choose your own namespace;
cleanup must remain confined to its recorded projects and labels.

## Native calibration and provenance

[releases.json](releases.json) pins Linux AMD64 image manifests, upstream source
revisions and installed source hashes. The native gates compare the installed
package and entrypoint with those references, before interpreting owner results.
The image's normal entrypoint remains responsible for starting motionEye.
Read-only fixture sources provide inspection and generated camera media.

The [upstream advisory](https://github.com/motioneye-project/motioneye/security/advisories/GHSA-j945-qm58-4gjx)
identifies 0.43.1b5 as the first fixed release. The fixed fixture uses the later
upstream 0.43.1 image. Its ordinary signed administration and genuine snapshot
functions must work while injected filenames are rejected without changing the
camera configuration.

[camera.py](camera.py) generates a red/blue JPEG test card and serves it over
loopback MJPEG. It supplies camera media to the actual Motion decoder. Native
snapshot checks inspect pixels, file bytes and ownership, rejecting placeholder
frames. Earlier HTTP-stream fixture attempts produced placeholders and remain
unqualified. No physical camera or downloaded sample recording is needed.

The gates verify genuine signed administrator requests, denied wrong/absent/
viewing-user credentials, persisted camera configuration, native snapshots and
an independent command-write or fixed-release refusal. A control camera remains
present while the owner creates and removes its own camera. Original web
processes, application sources, credentials and control configuration must remain
stable. Password profiles change credentials through the native configuration
API; they do not replace authentication handlers.

## Owner execution and cleanup

The functional suite calls the actual owner through msfconsole. It covers
automatic, disabled and forced checks; commands and repeats; quotes, dollars
and percent conversions; credential denials; missing paths and closed ports.
Bash and Linux HTTP-fetch tests require used, persisted and closed sessions.
Fetch cases cover x86/x64 stageless payloads and the x64 staged payload. Native
shell, callback, HTTP delivery and x86 executable controls run first.

The owner generates a camera address using Faker. The fixture selects a
deterministic Faker random source that produces `127.235.216.81`, and verifies
the actual address in each request. This keeps its generated camera on loopback
without replacing owner or network methods. Passive TracePoint observations
record real owner requests, checks, responses and executable delivery hashes.

Camera configuration removal is checked separately from stored media. The
application retains saved-image directories after camera removal. Fixture cleanup
removes only media paths observed in this run's native add/configuration replies,
rejects collisions with baseline paths, and verifies their removal. This is
explicit operator cleanup, not a claim that the module removes stored images.
Remote proof files, callback processes, sockets, channels, Framework jobs and
persisted session closure are verified separately.

The fixtures do not qualify other Unix operating systems, application prefix
deployments, literal multiline configuration values or unlisted payload families.
Existing human-written module Scenarios remain unchanged. Do not infer success
from an HTTP 200, an empty error field, a session-open message or this manifest.
