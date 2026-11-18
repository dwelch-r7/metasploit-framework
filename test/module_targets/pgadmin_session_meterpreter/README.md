# pgAdmin Meterpreter recovery regression

Run the strict staged/inline Python Meterpreter comparison separately:

```sh
bundle exec ruby tools/dev/run_guarded_module_target_tests.rb pgadmin_session_meterpreter
```

This retains real session, file/API and TCP-close assertions. Repeats disable
AutoCheck and use the same console configuration. RSpec is capped at 240 seconds;
setup/teardown have separate bounds. One stock 8.3 container uses the shared CPU,
memory and PID limits, native before/after controls and selected-state recovery.

The earlier unqualified 9/2 diagnostic proves file operations but leaves staged
sockets in CLOSE_WAIT after public shutdown. A later BentoML descriptor probe
identifies the inherited service-parent socket; the shared Python TCP stager now
closes its own copy after downloaded-stage execution. The child retains its own
connection. The [BentoML verification record](../VERIFICATION-20261118-bentoml.md)
records source-only repair evidence and the subsequent pgAdmin regression result.

No worker PID is signalled or garbage collection injected. Socket checks remain
strict. Recovery establishes selected files, channels and socket state; the full
disposable container/volume/network is removed afterward.
