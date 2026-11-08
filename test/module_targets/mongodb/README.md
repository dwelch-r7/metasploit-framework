# MongoDB targets

Run from the repository root:

```sh
bundle exec ruby tools/dev/run_module_target_tests.rb mongodb
```

Digest-pinned MongoDB 4.4.30 and 8.3.11 each run with authentication disabled and
enabled. Official image initialization creates public `rootuser` / `rootpass`
in `admin`, and `testuser` / `testpass` with readWrite on `intranet`.
The image's authentication-enabled bootstrap account is `admin` / `adminpassword`.

Native mongo/mongosh clients independently read real system credentials, nested
sample documents and 111 application hash records. A fresh unauthenticated
connection must read the marker on open targets and receive Unauthorized on
authenticated targets. A separate fresh restricted login must read its database
while being denied access to admin.system.users; it never reuses a root session.

The suite covers unauthenticated version detection and MongoDB 8.1+'s gated
buildInfo boundary, root/scoped/incorrect credentials, exact native SCRAM-SHA-1
and SHA-256 hash equality, permission failures and a cursor beyond the first
101 records. Schema loot must contain the real nested fields and preserve an
empty collection; rejected authentication must not produce hashes or schema loot.

Only random loopback database ports are published. Framework joins the target
network and uses an isolated configuration. Legacy MONGODB-CR, SHA-256-only
authentication, TLS, MongoDB versions between these two releases, credential
persistence/cracking and the separate Mongobleed module remain unqualified.
See [the shared guide](../README.md) for evidence and cleanup.
