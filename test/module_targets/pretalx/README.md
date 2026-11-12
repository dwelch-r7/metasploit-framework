# Pretalx schedule export lab

This isolated lab runs genuine community-distributed Pretalx 2.3.1 and 2.3.2
images, SQLite, one Gunicorn worker and one solo Celery worker. Redis delivers
the real export jobs. PostgreSQL records Framework reports independently.
Public fixture credentials and files exist only inside the disposable lab.

Run both profiles serially:

```sh
DOCKER_CONTEXT=default BUILDX_BUILDER=default bundle exec ruby tools/dev/run_guarded_module_target_tests.rb pretalx_2_3_1 pretalx_2_3_2
```

Four containers are capped at 1,312 MiB memory, two CPUs and 480 tasks in total.
Only the target HTTP port is published, on a random loopback port. Data, media,
exports and Redis state use temporary filesystems; teardown removes containers
and their single network. The vendor launcher's CPU-count-derived worker count
is replaced with explicit worker limits. Application vulnerability logic is
unchanged. Debug mode stays disabled.

The independent native control creates a separate conference and published talk
through native models, attaches an HTML resource, then uses real authenticated
HTTP requests to queue and download a Celery-generated export. It verifies the
normal schedule archive, exact affected-version proof bytes, patched omission,
wrong-password rejection and denied speaker access. Archive readiness requires
a complete readable ZIP. The owner's abstract-based route is tested separately;
native uploaded-resource success does not establish module success.

The acceptance cases call the public scanner check/run paths twice and check
exact stored loot and SQL reports. They cover affected/fixed versions, AutoCheck,
forced execution, disabled AutoCheck, spaces, missing/empty files, incorrect
credentials and insufficient organizer permissions. Current results and any
unresolved source failures belong in the dated verification report. No Windows,
alternate database, reverse-proxy prefix, custom media URL or newer UI is
qualified by these profiles.

Sources: [vendor advisory](https://pretalx.com/p/news/security-release-232/),
[research advisory](https://www.sonarsource.com/blog/pretalx-vulnerabilities-how-to-get-accepted-at-every-conference/),
[community image repository](https://github.com/pretalx/pretalx-docker).
