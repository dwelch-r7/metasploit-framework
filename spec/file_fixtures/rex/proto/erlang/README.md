# Actual Erlang RPC reply frames

`rpc_replies.json` retains actual complete TCP distribution reply frames from
authenticated hidden C-node connections to the genuine pinned RabbitMQ/OTP
profiles. The exact cookie-module request bytes were transmitted to the brokers;
the three commands return NIL_EXT, STRING_EXT and a Unicode LIST_EXT value.
Both versions returned SEND control tuples with a NEW_PID_EXT destination.
The requests themselves contain the old PID_EXT form, also decoded in specs.

The full native report, capture source and its owning-module hash are retained
in the qualification export. This reduced fixture records their checksums.
There is no simulated server. Fragmentation, truncation, alternate encodings,
unsupported terms and resource-budget cases in specs are explicitly derived
tests; they are not presented as native wire observations.

The decoder intentionally supports only the documented integer, atom, tuple,
proper-list, byte-string and PID forms needed for these RPC exchanges.
Unsupported forms raise a specific error. Protocol reference:
https://www.erlang.org/docs/25/apps/erts/erl_ext_dist.html
