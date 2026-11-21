# openDCIM Bash sessions

```sh
MODULE_TARGET_NAMESPACE=my-dcim-sessions bundle exec ruby tools/dev/run_guarded_module_target_tests.rb opendcim_sessions
```

This opt-in profile extends the pinned official openDCIM **24.01** and MariaDB
**10.11.9** [command fixture](../opendcim/README.md). Application source stays
unchanged. Apache supplies `REMOTE_USER=dcim`. A third, capped **128 MiB**
PostgreSQL service provides independent Framework session reporting. All three
services run only for this phase; Framework runs on the host. The application
and MariaDB retain their 768/384 MiB caps, with equal memory/swap limits.

Three examples cover real SQL/Graphviz/quoted-command readiness and a UID-33
callback control, an independent stock `cmd/unix/reverse_bash` session, and two
actual owner sessions on target 0. Native payload generation comes from the
running stock handler; its exact bytes are retained before execution as UID 33.
Only successful native readiness permits the owning session verdict.

The first owning run enables normal AutoCheck; the second disables it and reuses
the selected module. Both use the real HttpClient timeout default. Every session
executes a remote command, creates an exact-byte UID-33 proof, returns its PID,
responds again and exits. PID/birth disappearance, callback connection closure,
empty Framework jobs/sessions and the original reporting-row closure are
required. Ordinary Apache prefork workers may grow, but only UID-33 children of
the original root Apache process are accepted as additional idle processes.
All other process identities must return to baseline.

All 145 full configuration rows, seeded non-empty LDAP values, complete table
registry and installed source fingerprints must survive each session. The two
owner runs use distinct backup names. Original factory settings restore at the
end; proof files, containers and ephemeral resources are removed on every exit.

The stock image has **neither curl nor wget** in UID 33's normal PATH. That
prerequisite gap is recorded explicitly: this profile selects Bash and does not
qualify the automatically selected fetch payload. Dropper architectures/flavors,
HTTP authentication, other releases and patched behavior remain unqualified.
