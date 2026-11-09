# Erlang cookie command and session qualification

Run `bundle exec ruby tools/dev/run_module_target_tests.rb erlang_cookie` from
the repository root. This profile reuses the genuine pinned RabbitMQ/OTP targets
and independent controls from [the RabbitMQ lab](../rabbitmq/README.md), without
a Framework reporting database. Both brokers use the public fixture cookie
`MODULE_TARGET_ERLANG_COOKIE`. Distribution is real plaintext TCP on 25672,
not the EPMD discovery socket on 4369. The native controls verify correct and
rejected cookies using vendor `erl` RPC before invoking Framework.

OTP 24 accepts the historical distribution handshake while OTP 25 requires
version 6 capabilities. The independent control retains complete actual
handshake frames, receive chunk sizes, challenges and authenticated acknowledgments
for both peers, plus wrong-cookie refusals. It does not add a framing proxy or
artificially fragment TCP. Any derived fragmentation regression must be labeled
separately from these native captures.

The 12 examples exercise 13-, 255- and 256-byte Unix commands, rejected cookies,
`cmd/unix/reverse_bash` command-shell sessions and the Linux x64 printf command
stager with `linux/x64/meterpreter/reverse_tcp`. Each positive path runs twice.
Every command or fresh session must create a previously absent file owned by
the actual `rabbitmq` broker account. Proof files are removed and temporary
directory contents must return to their original state. Console completion or
an authentication banner alone is insufficient. Positive paths also reject operator
failure banners; only the wrong-cookie negative permits them.

The native completion gate also launches a genuine benign shell executable twice
per broker, receives each vendor Erlang RPC completion, confirms the background
process is alive and verifies exact directory restoration after native removal.
The module's Linux stager waits for replies addressed to its actual sender PID
with a `rex` result. Tick and unrelated packets cannot count as completion.
The existing command-stager background and `noconcat` options keep launch/removal
separate, with the ordinary 250ms inter-command delay preserved. The Linux distribution socket stays open across session registration until
all replies complete, then ensured disconnect closes it. Ordinary reverse
commands remain nonblocking. Windows stager timing is unchanged and unqualified.

The protocol references are the official
[OTP distribution protocol](https://www.erlang.org/docs/26/apps/erts/erl_dist_protocol.html)
and [External Term Format](https://www.erlang.org/docs/25/apps/erts/erl_ext_dist.html).
Handshake packets use 16-bit lengths; connected distribution packets use 32-bit
lengths. STRING_EXT lengths are unsigned 16-bit big endian. Version 6 challenge
layout differs from historical version 5.

This bounded profile does not qualify Windows, Linux x86, other command stager
flavors, other RabbitMQ/OTP releases, TLS Erlang distribution, EPMD enumeration,
CouchDB exploitation, or arbitrary external nodes. The separate CouchDB module
owns its own historical protocol implementation and is not modified by this lab.
Human module Scenarios remain intact.
