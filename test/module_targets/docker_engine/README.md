# Docker Engine version lab

Run `bundle exec ruby tools/dev/run_module_target_tests.rb docker_engine`.
Official digest-pinned Docker Engine 26.1.4 and 28.0.4 daemons run inside
ordinary containers. They use vfs, no bridge, iptables or forwarding, drop
SYS_ADMIN/SYS_TIME and receive no host socket, host filesystem or additional
capabilities. Their Unix sockets and anonymous data volumes belong only to
their containers. No nested workload or host escape is attempted.

Native Docker clients query each actual daemon over its own Unix socket;
independent HTTP requests must match its version document, accounting only for
the CLI's component build-time display format. Actual /info,
effective capabilities and Docker inspection verify the declared isolation.
An existing genuine Apache fixture proxies the modern daemon through Basic
authentication and TLS. Native TLS uses its actual certificate as a trust
anchor with the correct destination name. These are gateway policies, not
authentication features of the Docker daemon. Credentials are the public
module-test-user / module-test-password fixture. The generated certificate
and key are public lab material with no external trust.

Ten cases cover both versions with VERBOSE enabled/disabled, Basic auth,
TLS, absent/rejected credentials, unrelated HTML/200 and HTTP/404. Positive
paths run twice and must persist exact native version, architecture, OS,
kernel and service/workspace data into a fresh migrated PostgreSQL database
without duplicate notes. Negative paths must create no host or note rows.
Native/API captures, SQL and teardown receipts remain in the runner output.
The legacy host model represents the vendor spelling `amd64` as canonical
`Unknown`, with its exact value preserved in `detected_arch`. Tests verify that
documented fallback; they do not claim a separate architecture-normalization repair.

Only Linux amd64 information gathering is covered. This lab does not qualify
daemon container creation, privilege escalation, cron delivery, Windows,
other architectures, mutual TLS or arbitrary authorization plugins. Published
ports bind randomly to loopback; teardown removes all owned containers,
networks and volumes. Upstream build caches remain available.
