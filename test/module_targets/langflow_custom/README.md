# Langflow custom component execution

The pinned official Linux amd64 Langflow 1.10.0 image runs its real Python 3.14.5
backend with auto-login disabled and configured local fixture credentials.

```sh
DOCKER_CONTEXT=default BUILDX_BUILDER=default bundle exec ruby tools/dev/run_guarded_module_target_tests.rb langflow_custom langflow_custom_disabled
```

Native controls independently verify authentication, the effective custom-code
policy, benign component creation and exact UID 1000 code-execution canaries.
Langflow evaluates a class body six times per request and the owner-style
legacy module-local decorator guard executes three times. Those observed counts
are recorded separately from the public owner's expected single payload execution.
No replacement endpoint or external AI provider is used.

The `langflow_custom` profile enables custom components. The
`langflow_custom_disabled` profile uses the same image and credentials with that
setting disabled; native canary requests must receive 403 without creating files.
This result does not establish the broader advisory's policy-bypass claim. Qualification and failures must be recorded in a dated
report; native calibration alone does not qualify the owner.

Public console tests require exact commands, complete shell and forked/nonforked
Meterpreter lifecycles, database closure, live health, exact remote PID removal
and the original process set. Each case repeats on the same selected owner.
The target, Framework and reporting database run serially with the shared caps
and full project cleanup. Source versions and native flow state are verified
before and after testing. An authenticated canary also snapshots the actual
backend process PID and complete builtin namespace keys through the API, then
removes its file. The enabled profile requires the same namespace after public
execution, so a leaked shared execution guard fails verification. This inspects
the backend itself; a separate Python process would provide the wrong oracle.
Other versions, worker topologies, TLS, paths and authentication modes require
separate qualification.

Login throttling stays enabled. Both automated profiles set the supported
`LANGFLOW_RATE_LIMIT_PER_MINUTE=100` allowance so repeated positive and negative
cases can run quickly from one Framework client. Native controls verify the
effective setting and perform six successful logins from one client. The image's
default five-attempt limit was independently observed to reject the sixth login;
that earlier failed suite is preserved as a fixture-budget failure. These tests
do not assert that the production-default limit permits this whole burst.
