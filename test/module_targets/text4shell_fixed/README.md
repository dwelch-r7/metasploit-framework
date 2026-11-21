# Commons Text fixed-library profile

See the [shared recipe](../text4shell/README.md). Commons Text 1.10.0 replaces 1.8
with the original GET-only controller. Native shell/Nashorn positive controls
must still work; the default interpolator and HTTP route must block execution.
The module's Safe result and ineffective owning calls are checked separately;
the source does not implement automatic check-before-exploit refusal.
