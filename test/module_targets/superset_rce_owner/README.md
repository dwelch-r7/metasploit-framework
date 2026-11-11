# Superset RCE owner investigation

This profile remains unqualified. The native controls and independent Python
session calibrations pass, and owning sessions executed commands. The owning Meterpreter baseline fails shutdown, while the repaired-owner shell
closes cleanly. A residual target row blocks strict state restoration; repeat
runs and later cases remain unqualified. See the [runtime investigation](../VERIFICATION-20261111-superset-rce-owner.md).
Registration or a running target is not qualification.

The target reuses the pinned genuine 2.0.0 preparation and its installed-source,
cookie, PostgreSQL and native SQL/permalink/deserialization controls. Four
containers are capped at 2,144 MiB and 2.15 CPUs. The guarded launcher requires an
empty inventory, serializes work, and retains the lock through capture/teardown.

Independent native payload/handler calibration must precede owning sessions.
The owner should obtain and use both Python Meterpreter and command-shell
sessions, repeat cleanly, report real account hashes, and restore pre-existing
binary permalink values. Two existing native-created permalinks and their salt
serve as canaries. State is compared before any operator repair. Query/audit/login
history and SQLite file bytes are excluded, with exact selected rows retained.
Failures remain unclassified until target, native controls and captures are read.

```sh
nice -n 10 bundle exec ruby test/module_targets/superset_rce_owner/run.rb
```

Five registered examples cover a passive check, incorrect key lists, absent
administrator identity, and two repeated executions of each Python payload
family. Native payload calibration generates the real payloads in Framework,
starts their actual handlers and executes them directly in the application
container before any owning exploit. A session must perform a filesystem
operation; read-only socket observations bind its reported PID to the native
connection and service UID. Shutdown requires target socket release and an
absent Framework session. Python shell commands run in short-lived subprocesses,
so the test uses their actual parent and does not demand a web-worker exit.

The database assertions require real nonreplayable hash cores with connected
service/origin/workspace rows. Their cracking format decodes back to the exact
native account hashes, and repeated runs must reuse the persisted rows. No
login validation is fabricated. The canary comparison runs before each case
and after each owning attempt, without native database repair.

The original owner corrupted the pre-existing permalink bytes. The reviewed SQL
hex/type repair restores all three original key rows exactly, including both
canary permalinks and their native salt. One newly created permalink row remains;
the suite does not repair or discard it before comparison. The owning Meterpreter baseline also leaves target sockets in CLOSE_WAIT after
shutdown; its cause remains unresolved. The repaired-owner shell releases its
socket and Framework session. These failures keep this profile out of qualified totals.

The independent SQL capture proves two exact native account hashes and their
connected service/origin/workspace graph. It shows lowercase service names and
one login per core. The draft assertions have been corrected accordingly; future
execution must verify Untried status and absent attempt timestamps. That status
query missed teardown in the recorded run, so those details remain unobserved.
These assertion changes and this documentation follow the last failed runtime;
no subsequent owner replay is claimed. Later negative and repeat paths remain
unqualified because state guards stopped them.
