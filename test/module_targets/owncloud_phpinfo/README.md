# ownCloud phpinfo collection

```sh
bundle exec ruby tools/dev/run_guarded_module_target_tests.rb owncloud_graph_0_3_0 owncloud_graph_0_3_0_prefix owncloud_graph_0_3_1 owncloud_unrelated
```

These serial profiles exercise the genuine ownCloud 10.12.1 vendor runtime,
Graph API 0.3.0/0.3.1 and an unrelated Apache server. Registration does not prove
qualification. Inspect passing current examples, native controls and cleanup.

The affected runtime uses the pinned official amd64 manifest. The fixed-app
adapter installs the complete 0.3.1 app from the application layer of the pinned
official 10.13.1 image, verifying its SHA256. It retains the 10.12.1 core, PHP,
Apache, entrypoint and server command. It does not represent a full 10.13.1
deployment. This avoids another large PHP runtime in the local Docker cache.
The app layer contains source; no opaque fixture binary or replacement HTTP
handler is checked in. [profiles.json](profiles.json) records the identities.

The [vendor advisory](https://owncloud.com/security-advisories/disclosure-of-sensitive-credentials-and-configuration-in-containerized-deployments/)
describes the exposed PHP test file and notes that disabling the app alone does
not remove it. The historical Marketplace download URLs now return 404. Native
probes verify the real installed app version, full app tree, test-file presence,
ordinary ownCloud status and successful/rejected WebDAV authentication.

Supported environment variables initialize PostgreSQL and Redis. The application
uses a separate database in the reporting PostgreSQL container. Native controls
verify its schema, PostgreSQL accepted/rejected authentication, Redis accepted/
rejected authentication, and addresses resolved in Framework's namespace.
SMTP and disabled object-store settings are public disclosure fixtures; their
secrets are not validated against external mail or object-store services.

Python HTTP/HTML parsing independently verifies all 16 supported filename
suffixes. Complete decoded phpinfo fields are compared with native environment
values, including spaces and HTML metacharacters. Actual loot is parsed with
the same independent Python parser. Default reads enable public HTTP tracing
and compare the complete actual response body with the saved loot, since PHP
includes volatile per-request values. Real PostgreSQL records prove credential
values, addresses/ports, origin, deduplication and Untried login status. No
credential is reported as authenticated merely because it was collected.

The root and `/owncloud` deployments cover default discovery, explicit roots,
explicit suffixes, TARGETURI, repeat execution, missing paths and refused ports.
Native pre/post probes preserve environment, app files and process identity.
The unrelated target reuses the bounded genuine Apache control.

One project runs at a time. Genuine ownCloud profiles have four containers capped
at 1,504 MiB/1.65 CPUs: ownCloud 512 MiB/0.35 CPU/128 tasks, PostgreSQL
192 MiB/0.2 CPU/64 tasks, Redis 32 MiB/0.1 CPU/32 tasks, Framework
768 MiB/1 CPU/256 tasks. Apache profiles have three containers totaling
960 MiB/1.3 CPUs. Only HTTP is published, on host loopback. All project containers,
networks and disposable data volumes are removed after each run.
