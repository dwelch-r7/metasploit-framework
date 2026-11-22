# CouchDB Erlang command and session paths

Run serially from the repository root:

```sh
MODULE_TARGET_NAMESPACE=my-couchdb-lab bundle exec ruby tools/dev/run_guarded_module_target_tests.rb couchdb_erlang couchdb_erlang_sessions
```

The [base profile](../couchdb_erlang/README.md) supplies genuine CouchDB 3.2.1 /
OTP23 and independent vendor RPC/EPMD controls. This profile installs genuine
Debian `wget=1.21-1+deb11u1` from the dated signed May 1, 2022 snapshot, without
changing CouchDB/OTP binaries. Current package URLs failed independently during
setup; the historical package index and selected version are verified separately.
The former `monster` cookie is explicitly configured through the stock entrypoint.

Five cases cover explicit Unix OpenSSL sessions, explicit Linux
x86/x64 Meterpreter payloads with automatic wget delivery, quoted ASCII commands
with AutoCheck disabled, and Unicode/CRLF commands. Positive owner paths run
twice. The ordering separately records an uncontaminated first automatic
selection before explicit family tests. The first draft wrongly assumed that
selection would be OpenSSL; the console instead selected a PHP payload. PHP is
absent in the stock image, so that automatic path remains a separate prerequisite
gap and is not qualified by the explicit OpenSSL case.
Each payload family first uses a stock handler/native vendor-RPC control; native
Linux ELF files come from the handler's real encoded payload and Framework EXE
helpers. Large control files use Docker copy and exact hashes rather than huge
command arguments. Native wget also fetches and verifies real CouchDB HTTP data.

Public session APIs and physical target checks correlate owner/payload, actual
UID5984, PID, kernel birth and exact file bytes. A fresh response precedes public
shutdown and physical session-PID absence. Temporary-file sets, service health
and empty Framework jobs/sessions are checked. No reporting database is used.
The OpenSSL payload's complete process ancestry/long-lived relay children are
not qualified by session-PID checks; whole-container teardown removes all target
processes. Source/fixture failures remain separate from native prerequisites.

The capped target/Framework pair is namespaced and immediately removed with
ephemeral volumes after each run. Windows, fixed-release/cookie policies, other
delivery families and wider network layouts remain separate work. This draft
must not be counted as qualified until its actual functional receipt passes.
