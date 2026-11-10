# Prometheus API and Linux node_exporter lab

~~~sh
bundle exec ruby tools/dev/run_module_target_tests.rb prometheus
~~~

This profile uses official pinned Prometheus 2.39.1 and 3.2.1 images and
node_exporter 1.9.1. The old node_exporter 0.15.2 image uses retired schema-1
manifests; Dockerfile.legacy installs the official release binary with its
published SHA256 onto the pinned modern base. Its actual legacy flags are
selected explicitly, without assuming modern flags exist.

Prometheus genuinely scrapes seven healthy targets using static, Docker DNS,
file and authenticated HTTP service discovery. Official Apache serves the
discovery document, authenticates its real public fixture account, validates a
Bearer header and proxies the actual exporter. It does not emulate a Prometheus
API or manufacture metrics. Prometheus itself supplies root/subpath, basic-auth
and empty-configuration endpoints. Public fixture credentials are:

- metrics-user / public-metrics-password for Prometheus/exporter basic auth;
- module-test-user / module-test-password for Apache discovery;
- public-prometheus-bearer-token for the protected metrics proxy.

API configuration redacts inline secrets. Tests compare the exact returned
YAML and extracted references/masked values; they do not claim recovery of the
hidden original password. Native accepted/rejected requests and actual scrape
health independently validate the configured credentials.
Static basic-auth output labels password-file references and redacted passwords;
those values do not create new usable-password credential records. Existing
discovery credential reporting remains outside this profile's database scope.

Native promtool validates configurations and metrics. Its exact legacy
microseconds naming diagnostic is retained as exit 3; other parser/lint
failures are rejected. Prometheus's own ingester and PromQL decode information
metrics independently of Framework's parser. Native uname, hostname, mountinfo,
network files, version binaries and real volume paths provide additional
controls. The quoted filesystem path is an actual task-owned mount, rather
than a supplied textfile metric. A backslash mount was rejected during native
preparation because the exporter itself could not stat its encoded path;
that evidence is retained separately.

Eighteen bounded cases cover API/exporter versions, root/subpath, valid/missing/
wrong auth, real empty targets, metadata-only node output, unrelated services,
exact YAML/target loot, credential references and repeated collection. Target
comparison retains all fields except volatile scrape timing, error and health;
raw documents are preserved and actual healthy targets are required separately.
No failing banner, runtime exception or generic completion message can qualify
a positive result.

The containers use private Docker networking and random loopback ports. They
mount only this public fixture directory, public proxy files and task-owned
volumes; no host root/proc/sys, Docker socket, host PID or host network is used.
Information describes the container namespaces and shared Linux engine kernel,
not a separately qualified physical host. Runner teardown removes every owned
container, network and recorded volume; built images remain cache.

Scope is Linux amd64. Windows exporter requires a genuine Windows target and
is not simulated or qualified here. Provider-specific cloud metadata requires
actual provider discovery and is not imitated with artificial labels. The
official metadata-only exporter still emits build_info, so it does not exercise
the mixin's zero-sample branch. Database persistence and every discovery provider
are outside this profile. Existing human module Scenarios remain unchanged.

References: [Prometheus configuration](https://prometheus.io/docs/prometheus/latest/configuration/configuration/),
[authentication](https://prometheus.io/docs/guides/basic-auth/),
[node_exporter](https://github.com/prometheus/node_exporter),
[official legacy release](https://github.com/prometheus/node_exporter/releases/tag/v0.15.2).
