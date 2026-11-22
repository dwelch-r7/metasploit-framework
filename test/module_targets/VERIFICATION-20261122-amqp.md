# Serial AMQP scanner validation

Two original scanner owners pass **18 examples / 0 failures / 0 pending**, with
**28 actual canonical-console module calls**. Production source is unchanged.
The complete valuable feasible-module inventory goal remains active.

| Profile | Genuine broker | Cases | Native Pika controls | Owner calls |
| --- | --- | ---: | ---: | ---: |
| [rabbitmq_old](rabbitmq_old/README.md) | RabbitMQ 3.8.16 / OTP24 | 9 | 10 | 14 |
| [rabbitmq_new](rabbitmq_new/README.md) | RabbitMQ 3.12.14 / OTP25 | 9 | 10 | 14 |

## Native prerequisites and owning behavior

The existing [shared recipe](rabbitmq/README.md) uses pinned genuine official
Linux/amd64 images, independent Pika 1.3.2 on pinned Python 3.12.12, generated
lab-only certificates and a disposable PostgreSQL reporting database. Vendor
CLI queries verify actual broker/OTP identity, accounts and root permissions.
Native controls independently decode real connection.start bytes, authenticate,
publish/get exact messages, reject wrong/remote-guest credentials, reject a
limited account's root-vhost access and accept its allowed vhost. Both TCP and
certificate-trusted, hostname-verified TLS1.2 controls must pass before modules.
The reporting database independently accepts correct TCP SCRAM credentials and
rejects an incorrect password.

The actual `auxiliary/scanner/amqp/amqp_version` output and service rows match
native product/version, cluster, platform and mechanism fields. The original
`auxiliary/scanner/amqp/amqp_login` runs over both transports, repeats successful
credentials without duplicates, rejects wrong passwords and recovers with the
correct password, rejects remote guest access, accepts valid limited credentials
and keeps the same login separate between workspaces. Direct SQL verifies real
credential type, origin, module, host, service, status and workspace associations.

The scanner authenticates through connection.tune without opening a vhost. Its
limited-account success establishes valid credentials; native Pika separately
proves that `/` is refused and `module-target` is usable. No Framework session
is expected or counted for these scanners.

The Framework container uses the checkout mounted read-only at its normal
working directory. Live SHA256 checks of both owner files and their scanner and
protocol clients match the host before and after module execution. Final vendor
queries assert zero AMQP connections, no queues in either vhost, unchanged
accounts and unchanged root permissions. Those assertions run in `after(:all)`
after every randomized example; hook errors would fail qualification.

## Failures retained separately

The first draft was intentionally interrupted before qualification because its
preservation assertion was a randomized example. Two new multiline-conditional
lint offenses were also corrected before the final replay.

The second attempt's older native controls passed, followed by eight passing
owner cases. A fixture local named `services` was overwritten by discovery SQL
rows through its enclosing Ruby closure. That broke workspace isolation and
teardown before their relevant owner calls. The later release was interrupted;
all 14 observed objects were removed. Renaming the selected-broker variable
repairs the fixture. Neither discarded attempt is credited as a passing profile
or classified as a production module failure.

The frozen final pair passes 9/0/0 on each release, with zero errors outside
examples. Functional RSpec time is 88.22 seconds for the older release and
51.93 seconds for the newer release, including native controls and database
setup. Complete cached-build/health/test/cleanup phases take 123 and 87 seconds.
All declared inputs remain unchanged throughout that replay.

## Resources, evidence and scope

The guarded runner's shared lock keeps the releases serial. Each project has
explicit task namespace/labels, at most four containers, 2688 MiB total memory
and swap caps, 2.75 CPUs and per-service PID limits. Immediately after native
controls it removes the client container, leaving three services for owner calls.
Complete Compose projects and anonymous volumes are removed before the next
release. Both interrupted attempts also finish cleanup.

Global inventories, including stopped containers, verify both local Docker
contexts empty. All **35 new/998 recorded task objects** are absent, including
networks and volumes. The user's one-off broader cleanup found both contexts
empty before this lab. No image/cache pruning or Docker restart was performed.

The final runtime is `20261122T034812-be40bb`, with frozen inputs, native JSON,
client-release IDs, source hashes, SQL rows, console logs, preservation records,
RSpec JSON and exact cleanup receipts. The campaign retains **297 cases / 65
profiles / 687 current inputs**, with **219 ordinary used/closed Framework
sessions** and **21 separately retained source-variant sessions**. The earlier
279-case input set remains byte-identical. Registered labs remain distinct from
qualified profiles.

Changed Ruby passes RuboCop with zero offenses. Module documentation preserves
human Scenarios byte-for-byte; login documentation is tidy-clean, while the
version document retains four existing heading warnings and one informational
missing-options notice. Dry runs retain the original combined 17 examples and
select nine per serial profile. The original combined profile and the Erlang
execution suite were not rerun or newly qualified by this checkpoint.

AMQP1.0, other brokers, alternate SASL/certificate authentication, TLS versions
other than1.2, clusters, IPv6, other releases and other network layouts remain
unqualified. No production source fix, PR or external comment is created.

**Summary:** Two native-gated scanner owners qualify in stated paths.
**What looks good:** Real source, protocol and reporting evidence; immediate
helper removal and verified cleanup on both success and interruption.
**Concerns:** Wider protocol/authentication/release coverage remains open.
**Suggestions:** Continue the source inventory and qualify those paths separately.
