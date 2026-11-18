# pgAdmin Meterpreter recovery diagnostic

This profile is **unqualified** and excluded from the four-profile qualification
command in the [shared guide](../pgadmin_session/README.md). Run it separately:

```sh
bundle exec ruby tools/dev/run_guarded_module_target_tests.rb pgadmin_session_meterpreter
```

It keeps strict staged/inline Python Meterpreter session, file/API and TCP-close
assertions. Repeats use AutoCheck disabled and the same console configuration.
The RSpec phase is capped at 240 seconds; setup/teardown have separate bounds.
One stock 8.3 container has the same CPU/memory/PID limits and native controls.

Earlier staged sessions perform real file operations, but their target sockets
remain CLOSE_WAIT past 15 seconds after public local session termination. Native
HTTP healthchecks already run every three seconds. Installed Python Meterpreter
2.0.257 has no explicit normal-shutdown transport deactivation; this supports an
investigation, not proof of handler execution or a particular live reference cycle.
The threaded deserialization namespace repair is separate from socket recovery.
No worker PID is signalled, no garbage collection is injected and socket checks
are retained. The full disposable container/volume/network is always removed.
