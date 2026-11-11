# Superset RCE native preparation — 2026-11-11

The native prerequisites pass on the pinned genuine Superset 2.0.0 target.
This is **native-only evidence**: no Framework console, exploit owner, payload
handler or session ran. The qualified campaign totals remain **186 modules,
128 profiles and 1,447 functional examples** from the
[version checkpoint](VERIFICATION-20261111-superset-versions.md).

Run the [native RCE preparation](superset_rce/README.md):

```sh
nice -n 10 bundle exec ruby test/module_targets/superset_rce/native_gate.rb
```

The extension reuses the unchanged three-container native gate, lock, supported
initialization and vendor launcher. Actual limits are 1,376 MiB and 1.15 CPUs;
only Apache publishes a random loopback port. Root verified all final captured
roles and limits. Capture reported no OOM kill or errors. Images and unrelated
volumes are preserved.

## Actual result

Run `msf-superset-native-20261111t054132-674966`, source `a93ea05f0a8`, naturally
exited zero at 05:43:03 UTC after starting at 05:41:32. The gate records passed
status, current inputs, zero capture errors and passed cleanup. Native cookie
controls also pass: nine installed-application commands and sixteen HTTP
requests, plus the gate's separate real PostgreSQL login/query. The new phase
records 22 native commands and 62 genuine HTTP requests.

Sixteen installed SQL Lab, database validation, dashboard, permalink and
key-value sources match the official release commit
`067495d954ee0015d35c1437245feb66984e4c49`. Full captured source bytes independently
hash to their recorded digests. Native clients use ordinary fixture-admin login;
the earlier controls independently establish cookie privilege escalation.
Gamma database creation is refused. An ordinary SQLite URI returns HTTP400
with the exact security refusal, while the driver-qualified URI maps the real
metadata database through the application API.

Two complete cycles each establish:

- Actual SQL account hashes equal independent read-only SQLite observations.
- A real SQL Lab tab, dashboard and two permalink rows are created and used.
- The release lazily creates its shared salt. Its stored UUID equals the
  namespace/key defined by installed source; the salt bytes remain intact.
- CSV binary values round-trip to the independently observed original bytes.
- A single-row SQL write stores the exact harmless pickle bytes; the other
  permalink and shared salt remain unchanged.
- A real permalink HTTP request invokes the installed deserializer and writes
  the unique expected marker inside the disposable application. The pickle
  returns the normal native data shape, allowing the expected redirect.
- Original permalink bytes are restored exactly and both links work again.
  Only the cycle's API/SQL state is deleted; a separately logged native command
  removes its observed marker. The next cycle begins with no such artifacts.

Selected accounts, datasource, dashboard, key values, SQL tabs and table schemas
return to baseline. The target observer is read-only and does not repair state.
Query/audit/login history and SQLite file bytes are outside that comparison.
Host code never unpickles target bytes. Native marker cleanup does not prove
that the Framework owner's cleanup works.

Root teardown passed eleven independent queries: exact absence of three
container IDs, two network IDs and two owned volumes; absence of project
resource labels; and an empty global container list. The whole 86-file run
imported byte-for-byte, with all 23 selected source inputs exact in the primary
worktree. The verified 111-file read-only seal manifest is
`7fd101f2f243efd431eef3634d3cf37c39128c87776849a2d54c7e5d997e7dae`.
Original source maps, paths and command bytes remain unchanged.

## Preserved setup failures

`c110b7` stopped before the driver-qualified mapping: the control expected422
for the ordinary SQLite URI, but the application returned400 and an explicit
security reason. Correcting that assertion does not change target behavior.
Its native cookie controls passed; no owner calls ran. Root exact cleanup
passed eleven queries. The 111-file original seal manifest is
`d4ddb3b18fa650ab4942080008a278380615df623f2f148eb80838b6781b4378`.

`113608` reached mapping, exact account hashes and permalink creation, then
incorrectly assumed the two permalink rows were the only key values. The third
row is the native lazy shared salt, verified against the official shared-entry
and base-command sources. The revised control binds its UUID, preserves its
bytes and removes only the newly created salt during teardown. Root exact
cleanup passed eleven queries. The 112-file original seal manifest is
`a20cda4cba7cb6b343ded48c1d4bce79afe471d04b7dbe6a2510e5655b9371da`.
Both failures naturally exited one and remain setup/assertion evidence.

**Summary:** Genuine native SQL/permalink/deserialization prerequisites and
repeat cleanup pass. No RCE owner qualification is added.

**What looks good:** Installed-source identity, independent HTTP/SQL/binary
observations, marker evidence, repeat execution and exact removal establish the
prepared target behavior beyond health checks.

**Concerns:** Owner binary restoration needs investigation using the actual CSV
captures. Its credential persistence, payload families, sessions, repeat state,
partial failures and cleanup remain unqualified. Fixed releases, rotated keys,
HTTPS and other datasource backends remain separate work.

**Suggestions:** Reproduce suspected binary cleanup against complete owner
source with captured values, then run the owner against these native-proven
prerequisites. Keep source-only results distinct from actual session evidence.
