# LinuxKI automatic Unix target payload

The console selects `cmd/unix/php/meterpreter/reverse_tcp` after switching the
module to target2 at this pinned Framework revision. The module metadata's Bash
recommendation alone does not establish the console's actual selection. This
profile preserves that automatic behavior: it sets TARGET2 and leaves PAYLOAD
untouched, records the selected value and requires actual session metadata/use.

Run `linuxki_unix_default_sessions` with the namespaced guarded runner. Before
any owning call, callback/ack and genuine package controls gate repeated stock
CLI and genuine-page command-wrapped PHP sessions. The PHP runtime and stdapi
must resolve to ordinary files matching their package manifest. Each session
has the same public/physical use-and-shutdown requirements as
[the shared fixture](../linuxki_sessions/README.md). Two owning calls reuse the
selected module and use distinct callback ports; the repeat disables AutoCheck.
There is no reporting database. Both capped containers are removed on every exit.
