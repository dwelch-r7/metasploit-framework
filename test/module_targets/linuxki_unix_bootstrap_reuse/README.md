# LinuxKI reused-owner bootstrap investigation

This diagnostic repeats [the fresh-selection control](../linuxki_unix_bootstrap_controls/README.md)
with the same selected owning module for both calls. Native controls, ports,
ordinary producer/runtime, TLV logging and the passive observer are identical.
Only the owner-selection policy changes. Run `linuxki_unix_bootstrap_reuse`
with the namespaced guarded runner after the fresh-selection profile finishes.

A passing instrumented repeat does not erase the retained uninstrumented
failure or establish that source behavior is reliable. Both capped containers
and their ephemeral resources are removed on every exit. No producer is replaced.
