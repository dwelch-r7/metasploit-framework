# Superset target preparation

This is an unregistered target preparation. The native launcher below is an
explicit operation; source preparation and syntax checks add no module
qualification. Runtime results are recorded separately, including failures.

The pinned Apache 2.0.0 image uses its installed supported database migration,
administrator creation and initialization commands, followed by its vendor
Gunicorn launcher. The actual launch, migration time, memory fit and installed
dependency compatibility still require a bounded native run. SQLite metadata
stays at the module's documented path. These settings do not replace application
handlers, cookie signing, database access or deserialization.

The native operation uses three services totaling 1,376 MiB and 1.15 CPUs.
Superset and PostgreSQL remain on an internal network; only the real Apache gateway also joins a public
bridge and publishes a random loopback port. PostgreSQL supplies both a separate
native datasource role/database and the Framework reporting database. All
accounts are artificial public lab material; owned volumes are disposable.
No Celery, Redis, example dataset download or dependency installation is added.

`native_http.py` prepares browser-cookie controls using real HTML CSRF fields,
cookie jars, the installed application's serializer and independently requested
user identities. It discovers the identity key from the actual authenticated
cookie, rather than assuming the owner's `user_id` field fits the installed
Flask-Login release. It requires a low-privilege refusal, actual administrator
identity, exact datasource credentials, bad-password/signature refusals and
unchanged logical application state. The native launcher first verifies the actual image/platform, installed
source hashes, package versions, initialized SQLite ownership and a separate
PostgreSQL login/query. It saves partial observations when a prerequisite fails. They do not establish SQL Lab or RCE behavior.

Before registration or module assertions, native controls must establish actual
image/version/source/library identity, initialized SQLite ownership, real user
roles and login/refusal behavior, the installed Flask serializer, independently
accepted forged-cookie identity, ordinary PostgreSQL queries and exact decrypted
datasource credentials. SQL Lab, permalink behavior and payload/session
calibration require separate genuine controls before RCE assertions. Record and
restore affected application objects explicitly; a session alone does not prove
cleanup.

The planned version comparisons are 2.0.0 default and rotated keys, 2.0.1 default
key and 2.1.1 secure configuration. Their original-owner check boundaries must
be measured before any repair. Cookie-key fixes and the later SQLite/pickle
chain fixes are distinct. Other versions, architectures, roles and payloads
remain pending individually.

## Bounded native preparation

```sh
nice -n 10 bundle exec ruby test/module_targets/superset/native_gate.rb --native
nice -n 10 bundle exec ruby test/module_targets/superset/native_gate.rb --native 2.0.1
```

Each invocation requires an empty container inventory and holds the shared
campaign lock. The default remains 2.0.0; 2.0.1 explicitly selects its pinned
image overlay and corresponding official installed-source hashes. A native
version comparison alone does not establish module check or run behavior.
The 900-second operation bounds serial pinned-image pulls, supported application
initialization and genuine HTTP/serializer controls. Pulls have a 600-second
command cap, readiness 240 seconds and native controls 240 seconds, each limited
by the remaining overall bound. It starts no Framework console or module.

Results, raw commands, HTTP bodies, exact source bytes, package identities and
partial failures go under ignored `tmp/module-target-superset/`. Independent
bounded capture and teardown run even after the operation deadline: container
logs/inspect/processes/cgroups, Compose down with owned volumes, exact collected
ID absence, project-label absence and global empty container inventory. Cached
images and unrelated volumes remain. Each new run starts with a fresh metadata
volume. Main-module tests and SQL Lab/RCE native controls remain pending.
