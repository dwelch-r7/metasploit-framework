# Pretalx startup-hook execution lab

This separate fixture retains the qualified file-collection lab unchanged. It
uses the same pinned genuine application releases, native database, serial asset
build and Celery exports. The execution profiles add actual site-administrator
permissions, a measured Python user-site directory and an explicit interpreter
trigger. A non-Python HTTP healthcheck prevents automatic repeated hook execution.

Run the profiles serially:

```sh
DOCKER_CONTEXT=default BUILDX_BUILDER=default bundle exec ruby \
  tools/dev/run_guarded_module_target_tests.rb \
  pretalx_exec_2_3_1 pretalx_exec_2_3_2 pretalx_exec_production
```

Four containers are capped at 1,312 MiB, two CPUs and 480 tasks. Application data,
the Python user-local directory and temporary payload files use capped temporary
filesystems. `/tmp` permits executable payloads, verified by copying and running
the image's actual `/bin/true` ELF. Only target HTTP is published on loopback.

The independent native control derives the exporter destination and decoded
resource path from measured runtime settings. It proves a normal export before
and after a traversal attempt, writes a benign `.pth` through a genuine uploaded
HTML resource, and starts exactly one new interpreter. The affected debug target
executes its marker; the patched target refuses the traversal; production mode
can write its error response but does not execute the uploaded content. Hook
removal and a second clean interpreter startup are verified.

Functional cases exercise public checks, Bash and fetched Meterpreter sessions,
command execution, quoted commands, AutoCheck controls and repeated runs. A host
observer watches actual Celery results and starts one target Python process only
after the specific export task finishes. Session proof, remote shutdown, PID
disappearance and closed SQL records must be observed before normal console reset.
The Bash payload can print a diagnostic when closing an unopened descriptor;
only the exact captured diagnostic is allowed, after the session lifecycle passes.
Negative targets use a shorter handler wait, but the observer still waits for
the actual export and interpreter to finish before asserting no execution.

The existing module installs a persistent startup hook and leaves a write vector
in its proposal. Tests explicitly remove the hook and neutralize that disposable
event's description before repeating. These operations are recorded as operator
restoration; they do not establish automatic module cleanup. Unexpected fallback
cleanup remains visible in separate journals. Dated reports distinguish source
defects, fixture failures and qualified results. No human Scenarios are generated.
