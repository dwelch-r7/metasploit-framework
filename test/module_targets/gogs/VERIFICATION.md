# Gogs qualification boundary

The `gogs_hooks` profile passed 10/10 functional examples on 2026-11-10 using
pinned genuine Gogs 0.12.3 at the root and 0.14.3 through the Apache `/gogs/`
proxy. The untouched owning-module baseline was 10 examples/5 failures; the
repaired run was 10/0 with unchanged main assertions, options and deadlines.
Its invocation is `20261110T153132-316b7c/gogs_hooks`, with 60 recorded inputs.
The owning repair is commit `f24e608060cf2ce66baeb9166ec0f2cc156d6abe`.

The complete native gate passed 73 CLI operations, 327 HTTP operations and
22 proof records. Two native payload calibrations precede the module cases.
Actual module sessions include two Linux x64 Meterpreter sessions through the
ordinary Bourne dropper and two Bash sessions. Commands run as the real git
UID 1000. Each execution case repeats twice using fresh module instances;
existing same-instance state reset is not covered. The fixture and module
flows use `master` as their default branch. Windows, x86 and other default
branches are not runtime-qualified by this Linux lab.

The prepared `gogs_rebase` 10-case and `gogs_rebase_fixed` 5-case profiles have
not run and remain unqualified. Registering their prepared Compose profiles is
separate from qualification. The original rebase owner is unchanged, and no
rebase or fixed-release execution result is implied by the hooks result.

The capture-backed focused corpus changed from 22 examples/10 failures to
22/0. Handler rows model `handler_klass` with mocks for ReverseTcp, BindTcp and
None; they are not real payload executions. BindTcp has a compatibility unit
check only. Actual Bash/Meterpreter proof comes from the functional evidence.
Five inherited owning Ruby offenses and one inherited documentation warning
remain unchanged; new Ruby offenses are zero.

Shell proof sends an explicit target exit, verifies native target PID absence,
then separately closes the host session through its supported API. That is
operator lifecycle cleanup, not automatic deregistration or a forced target
kill. Test-created proof files are separately removed by the observer. Exact
module repository restoration and module-created temporary files are checked
before and around the recorded operator restoration steps. Complete project
teardown then removes the owned containers, network and volumes.

The vendor picture paths retain nonfatal avatar-generation permission warnings.
Their original logs are preserved; the matched comparison did not change that
configuration. Avatar upload/generation and unobserved ancestor/FD states from
the two earlier aborted calibration attempts are not qualification claims.
