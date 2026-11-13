# Concrete CMS file-usage lab

Run the serial profiles with:

```sh
DOCKER_CONTEXT=default BUILDX_BUILDER=default bundle exec ruby \
  test/module_targets/concretecms/run.rb
```

Qualification is recorded in dated verification reports. Original 9.5.0 and
9.5.1 docker5 images are pinned to platform manifests. They contain their normal
MariaDB, Nginx and PHP-FPM services; no application response or permission check
is simulated. The lab verifies 16 original core files on 9.5.0 and 14 on 9.5.1,
plus absence of the removed controller/view. Both images use PHP 8.2.35.

Original APIs import generated PNG images, create public and private/draft pages,
add real image blocks and track two page versions. One uploaded image is unused.
Anonymous controls must be redirected to login for the private page, while an
administrator can view it. Unauthenticated usage responses on 9.5.0 disclose the
private path; 9.5.1 returns 404 for the removed endpoint. An ordinary site, wrong
and correct logins and unchanged usage rows are independently verified.

Application profiles run serially with three containers capped at 1,920 MiB,
2.7 CPUs and 576 tasks: target 1,024 MiB, Framework 768 MiB and reporting database
128 MiB. Only application HTTP is published on loopback. Reporting state is in a
bounded temporary filesystem. Image application data is discarded at teardown;
no persistent Docker volume is created. Vendor code remains in its pinned image
and is hashed before and after testing; configuration, database and upload/cache
paths are writable through the application's normal APIs.

The `/cms` profile changes only the Nginx document root/front-controller fallback
and places the original site behind a symlink. Core controllers and views remain
byte-identical. The unrelated control reuses the existing Apache fixture.

The stock image needs no package install or network access on startup. Docker
image pulls are one-time setup. Existing human Scenarios remain unchanged.

Functional cases cover a single file, private-only references, multiple blocks
and page versions, a range containing an unused image, empty/nonexistent IDs,
the default 50-ID scan, missing paths and a refused TCP port. Each owning case
runs twice. A separate workspace per case checks PostgreSQL vulnerability
persistence and repeat behavior, alongside exact CSV rows derived from the
application's real page/usage models.
