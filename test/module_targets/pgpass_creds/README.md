# PostgreSQL password-file collection target

This opt-in profile exercises `post/multi/gather/pgpass_creds` using a genuine
PostgreSQL server/client target, a separate ordinary reporting
database and a capped Framework console on the same Docker network. Both declared
session types, Linux shell and Linux Meterpreter, must run real generated ELF
payloads with actual UID/PID/session proof. No module result is inferred from
native client success or console completion alone.

```sh
bundle exec ruby tools/dev/run_guarded_module_target_tests.rb pgpass_creds
```

The target pins the existing PostgreSQL image digest: server/client 16.15 on
Debian 13, linked libpq 18.6, with Python 3.13.5. Native root and ordinary-user
psql controls authenticate through real mode-0600 password files. Wrong passwords,
over-broad permissions and missing files must fail. Blank/incomplete lines,
wildcards and escaped fields require native acceptance before owning expectations.
Each selected home file is authenticated immediately before collection.

The sixteen cases cover plain/repeated collection, comments, blank/incomplete
lines, wildcard host/port and escaped database/user/password fields with each
session type. Actual raw loot and session-origin
credential/login/realm rows are checked. Native successful authentication remains
separate from the owner's Untried reporting status. Recovery verifies owned file
bytes, session process identity, database closure and generated-artifact hashes;
generated source payloads remain in the private evidence directory.

One serial stack has at most three containers: target 0.5 CPU/512 MiB, reporting
0.25 CPU/384 MiB and Framework 1 CPU/1,536 MiB. Memory/swap, PID and init limits
are explicit; published database ports bind to loopback. Other platforms, client
or server releases and additional syntax remain unqualified. Five additional
escape/empty/trailing boundaries have source-backed unit contracts, without
native authentication claims. Legacy collection of unescaped password colons is
preserved; it differs from libpq and is outside native qualification. Preserve and
classify native, session, harness and owner failures separately before repairs.
