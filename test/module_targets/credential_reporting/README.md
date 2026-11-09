# Database-backed credential reporting

```sh
bundle exec ruby tools/dev/run_module_target_tests.rb credential_reporting
```

This profile reuses the genuine [PostgreSQL](../postgres/compose.yaml),
[SSH](../ssh/README.md) and [Apache](../http/README.md) authentication targets.
A separate digest-pinned PostgreSQL instance stores Framework data. It starts
with an empty schema; the ordinary `db_connect` command performs Framework's
real migrations. It never connects to an existing operator database.

Native psql, OpenSSH and Net::HTTP controls first establish valid/rejected
credentials and actual target identity. Direct psql queries inspect persisted
credential, origin, login, host, service and workspace records independently
of Framework's ORM/output. Eleven cases cover repeated password/key reporting,
incorrect-password/key negatives, workspace isolation and real `creds` CSV export.
An independently generated authorized key establishes native SSH access; another
key is refused. Recovering the stored key through SQL must permit native OpenSSH
authentication. Password/key records for the same account stay distinct, and
host/origin/login relationships must retain their correct workspace and service.
No sessions are created. All credentials are public fixtures.

The persisted fields follow the actual migrated schema. It has no login-proof
column; native authentication evidence and module transcripts remain in the run
artifacts rather than being claimed as persisted proof.

Only random loopback target ports are published; the reporting database stays
on the isolated project network. The [shared runner](../README.md) retains
commands, native snapshots, image identities, exact counts, input hashes and
owned teardown. Registration alone does not mean qualification.

This profile qualifies the asserted password paths and local PostgreSQL data
service. Other modules, credential types, authentication modes, remote HTTP
data services and persistence across server upgrades remain separate work.
