# Langflow authenticated code validation

This profile uses the real Langflow 1.8.4 backend pinned by digest, with
`LANGFLOW_AUTO_LOGIN=false` and configured local fixture credentials. No external
AI provider or replacement endpoint is required.

```sh
DOCKER_CONTEXT=default BUILDX_BUILDER=default bundle exec ruby tools/dev/run_guarded_module_target_tests.rb langflow_execution
```

Independent native controls require anonymous validation to return 403, an
incorrect password to return 401, and a valid login to accept benign code. Both
Python default arguments and decorators must produce exact UID 1000 file bytes;
the controls remove those files and preserve the authenticated flow registry.
Installed validation source hashes and vendor package versions are checked.

The public console cases exercise version detection, incorrect credentials,
AutoCheck disabled, exact command output, Python command shell and staged Python
Meterpreter, missing paths and refused ports. Every case repeats on the same
selected owner. Sessions must execute commands or write files, match database
provenance, close their transports and leave no callback connection or job.
Persistent Python payloads need an HTTP response while their callbacks remain
active. A daemon thread runs the configured Python interpreter as a disposable
subprocess and waits for it. This preserves the backend's responsiveness and
keeps payload sockets and forked processes out of its persistent interpreter.
A native version request must succeed while each session is open. The session
cases allow 12 seconds for Framework bootstrap, including its command-shell
banner read. Staged Meterpreter runs both with its normal fork behavior and
with `MeterpreterTryToFork=false`.

Each session must have a real separate UID 1000 process. Shutdown must remove
that exact PID/birth identity, close its database row, and restore the complete
original process set without extra active or defunct children. The authenticated
flow registry also stays unchanged. Native calibration showed that inline
`python/exec` can retain an exited Popen child and inline Meterpreter forking can
leave a duplicate socket and zombie in the backend. Those failed runs remain
recorded separately; the worker-process design must pass the strict baseline.

The three-container resource caps are target 3,072 MiB/one CPU, Framework
768 MiB/one CPU and reporting database 128 MiB/0.2 CPU. Published ports bind to
localhost, swap equals memory, and Compose cleanup removes the whole project.

Scope: Linux amd64 Langflow 1.8.4 with one backend worker, this validation owner
and the explicitly exercised Python payloads. Other versions, TLS, URL prefixes,
authentication providers and other Langflow exploit owners need separate tests.
Native calibration does not establish Framework functional qualification. Use
the dated verification report for actual console results and remaining limits.
