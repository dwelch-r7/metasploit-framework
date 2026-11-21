# Salt REST API command lab

This profile uses the source-pinned Salt 3000.1 runtime from the
[ZeroMQ lab](../saltstack_zeromq/README.md), adds locked CherryPy dependencies
and runs ordinary `salt-master` and `salt-api` daemons with HTTPS. The real
OpenSSH client is installed from the signed Debian snapshot dated 2024-01-01.
Salt source, API responses and command execution are unmodified. An empty SSH
roster contains the lab while retaining Salt's real key-generation path.

```sh
bundle exec ruby tools/dev/run_guarded_module_target_tests.rb salt_api
```

The native gate verifies seven installed source files against official release
archives, real daemon configuration and TLS state, valid and invalid sharedsecret
authentication, rejection of missing authentication fields, ordinary SSH key
generation and an authorized SSH API request. Independent CLI and API calls must
write exact root-owned plain and quoted Unicode/CRLF proof bytes before the owner
is invoked. The fixture credentials are disposable lab configuration.

Functional cases exercise repeated real checks, two original command executions
with AutoCheck on and off on one module selection, a refused port and AutoCheck
refusal. Passive TracePoint records retain original method locations, command
bytes and raw HTTP requests/responses. Configuration, TLS files, roster and the
`/dev/null` device must remain unchanged after each call. The actual literal-path
directories created by Salt's vulnerable key generator are recorded separately
before fixture removal; that removal is not credited to module cleanup.

One container is capped at **512 MiB, 0.7 CPU and 160 tasks**. Only a random
loopback HTTPS port is published. Runtime keys, caches and logs use bounded
tmpfs. Every run uses the guarded runner's unique project namespace, lock and
unconditional teardown. Follow the repository's container lifecycle policy and
remove the stack immediately after testing, including stopped containers.

Salt 3000.1's Linux package metadata requires `pycrypto`, while its source
explicitly supports and prefers the installed pinned `pycryptodomex` backend.
The build accepts only that exact metadata discrepancy and verifies Salt loads
Cryptodome. Every other package conflict or missing SSH/TLS tool fails the build.

Registration and native readiness do not qualify the owner. Consult the campaign
verification report for actual results. The default SSL Python session, Linux
dropper, fixed releases, alternate base paths and other Salt modules require
separate native controls and remain outside this profile's claim. The upstream
[security fixes](https://github.com/saltstack/salt/pull/58871) distinguish command
injection from authentication bypass; do not infer both from an HTTP status.
