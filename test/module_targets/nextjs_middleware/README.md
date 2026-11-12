# Next.js middleware authorization bypass lab

Five serial profiles exercise genuine Next.js 15.2.2 and 15.2.3 production
servers, with middleware at the project root or under `src/`, and an unrelated
Apache control. The [vendor advisory](https://github.com/vercel/next.js/security/advisories/GHSA-f82v-jwr5-mffw)
identifies 15.2.3 as the fixed release for CVE-2025-29927 on this branch.

```sh
bundle exec ruby tools/dev/run_guarded_module_target_tests.rb nextjs_middleware_root nextjs_middleware_src nextjs_middleware_fixed_root nextjs_middleware_fixed_src nextjs_middleware_unrelated
```

The Dockerfile pins the official amd64 Node base by digest. Version-specific
package locks pin Next.js, React and transitive dependencies by registry
integrity. The fixture builds its small application with normal `next build`
and starts it with normal `next start`. Build configuration uses one compiler
CPU and a bounded Node heap. No Next.js source or HTTP response is replaced.
The unrelated profile reuses the existing genuine Apache HTTP fixture and its
Basic-authenticated resource, including accepted/rejected native credentials.
All five crafted header values must leave that unrelated 401 gate enforced.

This is a real application whose authorization is implemented in middleware.
It protects a dashboard, an API, a forbidden resource and a 302 redirect route.
Accepted and rejected session cookies, 307/302/401/403 gates, protected content,
modern recursion depth and both middleware module names are independently
verified. Public and nonexistent paths remain ungated. Ordinary trailing-slash
normalization is recorded separately because it precedes the protected route.
The `X-Powered-By` banner is disabled through the normal Next.js option.

Native probes compare four installed vendor files with verified official npm
artifacts, verify application sources and production build identity, inspect
real HTTP behavior and validate separate reporting PostgreSQL credentials.
Functional tests invoke public `check` and `run`, inspect real service/CVE/loot
SQL, test repeats, forced payloads, cookies, missing paths and a refused port.
Cookie header files contain only public fixture values and live in each run's
artifact directory. No external account or identity provider is used.

Registration and native preflight do not qualify the module. Consult the campaign
verification report for actual results. This lab covers Next.js 15.x behavior;
older affected branches and deployment platforms need their own qualification.

Application profiles have three containers capped at **1,216 MiB/1.5 CPUs**:
Next.js 320 MiB/0.3 CPU/128 tasks, reporting PostgreSQL 128 MiB/0.2 CPU/64 tasks
and Framework 768 MiB/1 CPU/256 tasks. Apache control totals 960 MiB/1.3 CPUs.
Only HTTP is published, on a random loopback port. Bounded tmpfs holds Next's
runtime cache and the disposable reporting database. No named or anonymous data
volume, privileged container or Docker socket is required. Run one profile at a
time and remove its entire project before starting the next.
