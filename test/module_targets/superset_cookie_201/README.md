# Superset 2.0.1 version boundary

This profile compares unchanged owner checks with a genuine pinned 2.0.1
application. Its independent native-only run confirmed default-key cookie
escalation, administrator identity, exact datasource secrets and ordinary
PostgreSQL authentication. Native success alone does not qualify an owner.

```sh
nice -n 10 bundle exec ruby test/module_targets/superset_cookie_201/run.rb
```

Four short cases require both Superset checks to recognize the native-proven
cookie condition, exercise the gatherer's default AutoCheck path, and compare
actual SQL rows across two explicit `ForceExploit` runs. Initial failures remain
evidence for investigation. The RCE owner is exercised through `check` only;
its exploit, payload, session and target cleanup paths remain unqualified.

The target uses the [shared native preparation](../superset/README.md), supported
initialization and original vendor launcher. Four containers stay within
2,144 MiB and 2.15 CPUs. Native controls run before and after owner calls, with
exact selected logical state comparison. PostgreSQL datasource authentication
is checked in each invocation as well as connected Framework credential rows.

The default target for the separate fourteen-case cookie profile remains 2.0.0.
The two releases run serially with fresh owned metadata and volumes. All roles
and script source remain real; no application handlers or module responses are
replaced. The supplied example users and credentials are disposable lab data.
