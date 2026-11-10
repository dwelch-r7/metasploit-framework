# Genuine clients of Framework capture servers

```sh
bundle exec ruby tools/dev/run_module_target_tests.rb capture_core capture_mail
```

The sixteen-case core profile runs the FTP, HTTP Basic and PostgreSQL
capture modules as actual Framework jobs. The sixteen-case [mail profile](../capture_mail/README.md)
shares the genuine clients for SMTP, POP3 and IMAP. These modules intentionally
impersonate servers: the listening service under test is the Framework module,
and the targets are real libcurl, libpq and Python standard-library clients.
No test protocol server substitutes for a module.

Client setup is independently authenticated against the existing genuine
ProFTPD, Apache and PostgreSQL fixtures before any capture job starts. Controls
verify real file/HTTP content and SQL identity, rejected credentials, and exact
client packets. The image pins curl 8.13.0; the pinned PostgreSQL image provides
psql 16.15 linked to libpq 18.6, recorded separately. Python 3.13.5 and tcpdump
are version-pinned target-only dependencies, with complete package inventories.
No Framework project dependencies are installed or modified.

All services have no published ports. Curl shares the dedicated client namespace,
where tcpdump captures only the selected owned protocol port. Actual PCAP and
reassembled TCP payloads are retained. tcpdump uses immediate mode; capture
controllers require real application payloads and stop their own process on
completion. Neither capture listeners nor clients use host networking or sockets.
The runner's Framework listener address is the isolated Framework container IP.

Cases cover FTP normal and surrounding-space/colon/quote/backslash passwords,
USER without PASS, and a password the genuine fixture rejects. HTTP covers
challenge/preemptive Basic, blank passwords, redirects, absent/unrelated requests
and a valid non-Basic scheme containing the word basic. PostgreSQL uses real
libpq sslmode disable/prefer/require, spaced role/database names and missing
passwords; GSS encryption is explicitly disabled to isolate those paths. Native
PostgreSQL without TLS refuses require without receiving a password. This does
not qualify direct TLS, GSS or other PostgreSQL authentication mechanisms.

Each ordinary case runs twice with a fresh job on the same port. Direct SQL
checks exact client address, listener port, protocol/service, module/service
origin, workspace, private bytes/type, UNTRIED status and an unset validation
timestamp. Repeated captures must not duplicate credentials; an explicit
workspace option must remain isolated when the console workspace changes.
Captured credentials are not promoted to validated target logins, even when
a capture server emits a protocol authentication-success response. Capture
clients may finish with protocol refusals after transmitting their
credentials; exact reporting is the acceptance condition. Their independent
genuine-server controls must complete successfully first.

The installed credential API/model has no persisted login proof field and ignores
its proof option. The profile records actual wire/client proof separately and
retains the migrated schema; it does not invent a login.proof column or silently
change the dependency. Blank passwords use the model's BlankPassword subtype.

TCP jobs must disappear and their listener ports close. HTTP cleanup is tested
with two real HTTP Basic jobs on one pooled listener: after the capture job is
stopped, its URL must actually return 404 while the guard URL still returns 401.
The guard has a distinct workspace and must capture no credentials. After the
last job stops, all owned resources must be removed; any retained empty pooled
listener is recorded and must actually serve 404, rather than being called closed.
The final Compose teardown and recorded volume absence are separately audited.

See the [shared runner guide](../README.md) for exact-count, source/input hashes,
transcripts and owned teardown. Fragmented/long commands and coalesced commands
remain unqualified: FTP/POP3 still read one command per `get_once`, and PostgreSQL
requires a complete Startup message in one callback. Windows, IPv6, TLS listeners,
other clients and authentication extensions remain unqualified.
Existing human module Scenarios are preserved.
