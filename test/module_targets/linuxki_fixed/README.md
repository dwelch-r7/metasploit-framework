# LinuxKI fixed-release control

Run `linuxki_fixed` with the same guarded runner described in
[the vulnerable fixture](../linuxki/README.md). It installs the genuine pinned
6.0-2 vendor DEB and reuses the shared native/owner controls.

Three examples independently establish CLI/interpreter readiness and rejection
of exact command effects, observe the actual Safe check, and refuse default
exploitation twice on the same selection. Native requests include a valid
`1111_1111` timestamp to reach numeric `pid` sanitation, plus the missing-timestamp
request shape emitted by the module. The owner's Safe result by itself only
demonstrates that latter early refusal. No vulnerable execution/session coverage
is credited to this profile.
