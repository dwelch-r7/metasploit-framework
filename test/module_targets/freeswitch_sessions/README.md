# FreeSWITCH session and Linux dropper validation

```sh
DOCKER_CONTEXT=default BUILDX_BUILDER=default bundle exec ruby \
  test/module_targets/freeswitch_sessions/run.rb
```

This matrix is under development. Dated verification reports establish actual
qualification; a profile or passing native prerequisite alone is not a module
verdict. The existing command/check fixtures remain unchanged.

Two Unix profiles cover Bash, Perl and default double-telnet command shells with
default and Unicode/space passwords. Two Linux profiles cover x86/x64 shell and
Meterpreter payloads through curl and wget stagers. Every payload first receives
independent handler/native execution calibration, then two real owning runs.
Native calibration uses the actual already-generated handler payload under the
owner's bad-character constraints. It never replaces owning methods or rewrites
payload encoding after handler startup.

Controls use real session RPC/commands, exact marker bytes/UID, actual peer,
socket-owning processes and process birth. Perl creates a disposable child per
command, so its reported shell PID is not treated as the persistent interpreter.
Transport shutdown, database closure, process/socket disappearance, file cleanup
and a second owning run establish repeatability. Only an observed new telnet
sleep feeder can receive explicit operator cleanup, with its PID/birth/UID
recorded. This cleanup is separately calibrated natively.

The genuine original FreeSWITCH binaries and pinned native tool packages remain
unchanged. Each profile uses three capped containers: target, Framework and
reporting PostgreSQL, totaling 1,664 MiB, 2.5 CPUs and 576 tasks. Profiles run
serially under the existing five-container hard limit. Windows requires another
suitable environment and is not qualified by these Linux containers.
