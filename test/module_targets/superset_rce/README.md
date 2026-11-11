# Superset RCE native preparation

This native-only gate prepares the separate RCE owner investigation. Runtime
qualification is recorded in campaign reports; adding these controls does not
qualify the module or establish a session.

```sh
nice -n 10 bundle exec ruby test/module_targets/superset_rce/native_gate.rb
```

The gate extends the [existing genuine 2.0.0 target](../superset/README.md) and
retains its native cookie, role, source and PostgreSQL controls. Three serially
owned containers remain capped at 1,376 MiB and 1.15 CPUs. It acquires the shared
lock and requires an empty inventory. The standard native gate captures raw
failures and removes its exact containers, networks and volumes before returning.
No Framework console or exploit module is invoked.

The added installed-source checks pin SQL Lab, database validation, dashboard,
permalink and key-value commands to the official release commit. The native
HTTP client independently authenticates the fixture administrator; earlier
cookie controls prove privilege escalation separately. It tests ordinary user
refusal, the ordinary SQLite URI refusal and the driver-qualified metadata
mapping. Two cycles exercise actual SQL account hashes, dashboard/permalink
creation, CSV binary values, a single-row SQL mutation and harmless pickle
execution that writes a unique marker inside the disposable application.

Each cycle restores exact original permalink bytes, verifies the other row,
deletes only its own API/SQL state, compares account/datasource/dashboard/key
state and SQL tabs, and removes its observed marker. The independent target
observer is read-only; it never repairs database state. Marker removal is a
separate explicitly logged native filesystem command. Query/audit/login history
and SQLite file bytes are outside the logical comparison. Native success does
not establish owner cleanup, payload delivery or session behavior.
