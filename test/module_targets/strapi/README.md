# Strapi administrator password-reset lab

Run the complete preparation and test pipeline serially from the repository root:

```sh
DOCKER_CONTEXT=default BUILDX_BUILDER=default bundle exec ruby \
  test/module_targets/strapi/run.rb
```

Preparation uses one container capped at 768 MiB, 0.7 CPU and 128 tasks. Pinned
npm lockfiles install the original beta.17.4 and beta.17.5 packages without
installation scripts. Thirteen authentication/query files per release must
match the official Strapi source tags. A versioned cache under
`tmp/module-target-strapi-dependencies` avoids large duplicate Docker image
layers. Preparation verifies existing caches and removes its containers.

Each functional profile uses four containers capped at 1,664 MiB, two CPUs and
512 tasks: Strapi 512 MiB, MongoDB 384 MiB, Framework 640 MiB and reporting
PostgreSQL 128 MiB. Only target HTTP is published on loopback. Vendor dependencies
and fixture sources are mounted read-only; generated application settings and
MongoDB data use capped temporary filesystems. The supported `serveAdminPanel`
setting disables only the browser frontend; genuine JSON routes, controllers,
JWT/password services and MongoDB models remain active. No successful responses
or authentication handlers are simulated.

The module's request requires an administrator with a pending reset token.
The independent control proves registration, incorrect/correct login, refusal
without a token, a legitimate known-token reset, and the malformed-token path
on both original releases. Tests seed the ordinary reset-token database field
as explicit lab state; SMTP delivery is outside this lab. They verify old/new
password acceptance, token consumption, repeated runs and actual Framework
credential/service records. Checks, complex passwords, fresh/consumed tokens
and absent administrators are exercised through public console commands.

The existing module guide retains its human-written Scenarios. Dated verification
reports distinguish native setup failures, source defects and qualified results.

Application configuration derives from the original
[`strapi-generate-new` beta.17.4 generator](https://github.com/strapi/strapi/tree/v3.0.0-beta.17.4/packages/strapi-generate-new/lib/resources/files),
with lab database/server settings and unused sample keys removed. Its
[MIT license](APP-LICENSE.md) is retained.
