# Salt master/minion execution lab

This profile runs a genuine Salt 3000.1 master and two minions using the pinned
source-built image from the [collection lab](../saltstack_zeromq/README.md).
Normal Salt daemons, key acceptance, encrypted minion traffic and command APIs
remain intact. A small supervisor gives each daemon a distinct environment
marker so sessions can prove their execution role even on a shared host.
Docker's init process reaps adopted children; no application source is patched.

```sh
bundle exec ruby tools/dev/run_guarded_module_target_tests.rb saltstack_rce_3000_1
```

Native controls verify thirteen vendor files, fifteen locked runtime packages,
configuration, accepted node keys, ordinary authenticated commands, root-key
acceptance/rejection, and selective/all/missing PCRE publications. Real markers
must match each executing daemon's token. Publication acknowledgements alone do
not establish command execution.

Functional cases exercise all four exploit targets with their default payload
families, repeated genuine sessions, check-derived and provided root keys,
selective multi-minion execution, wrong credentials and a refused port.
Session RPC or command APIs write proof files, expose actual execution identity
and link to persisted SQL sessions. The SSL command payload executes a fresh
shell for each command; its connected owning process is verified separately.
Session processes, sockets, listeners and jobs must close before another run.
The concurrent Python minion case runs before any other Meterpreter case and
asserts that the Stdapi class is still unloaded. This preserves coverage of
cold extension initialization; a prior single session must not conceal it.
An independent SSL command payload control uses the ordinary handler's generated
bytes through legitimate authenticated Salt RPC. This calibrates the payload
transport; it does not establish unauthenticated exploitation. Actual Salt job
returns are retained alongside the owning module output for diagnosis.

Three containers are capped at **1,408 MiB/1.7 CPUs**: the cluster uses
512 MiB/0.5 CPU/160 tasks, reporting PostgreSQL 128 MiB/0.2 CPU/64 tasks and
Framework 768 MiB/1 CPU/256 tasks. Only a random loopback return port is
published. Runtime state uses bounded tmpfs and configuration mounts are read
only. Keep this profile in the same single serial queue as every other lab.
This lab overrides `/tmp` with a bounded executable tmpfs because Salt's
`cmd.script` executes its downloaded file directly. A native script probe verifies
the mount before and after functional testing. Compose 2.24.4 or later is required
for the [`!override` merge tag](https://docs.docker.com/reference/compose-file/merge/#replace-value);
the collection lab remains unchanged.
Positive calls use a 15-second WfsDelay to allow both minions to connect under
the shared CPU cap. Negative calls use shorter waits after native-proven denial.

Registration is not qualification. Consult the campaign verification reports
for actual results and classified failures. This profile does not qualify
2019.x, fixed releases, separate hosts, other products, or Salt post modules.

The current nine-case session run passes, but minion workers still report
`KeyError: 'ret'` after both native custom and owning publications execute.
Return metadata and job completion require further validation before this
profile is qualified. The two minions use distinct cache directories, so the
module's hardcoded default proc-file cleanup path is also not covered here.
