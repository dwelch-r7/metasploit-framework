# openDCIM Linux dropper sessions

Four [dropper profiles](opendcim_dropper_x64/README.md) pass **12 examples / zero
failures / zero pending**, with **12 used/closed Meterpreter sessions**. Four
independent native controls precede eight actual target-1 exploit sessions. Both
architectures and both declared stager flavors are exercised. Production module
source is unchanged; no PR is created. The broader inventory goal remains active.

## Target and native prerequisites

The recipes extend the existing pinned official openDCIM **24.01** fixture,
PHP **8.1.2-1ubuntu2.14**, MariaDB **10.11.9** and reporting PostgreSQL. The
application installer creates the database; application source is unchanged.
Apache supplies `REMOTE_USER=dcim`. Native SQL/Graphviz/quoted-command controls,
seven source fingerprints, all 145 configuration rows and the table registry
must pass before session qualification. Thirteen non-empty LDAP values make
accidental configuration changes visible. A real UID-33 TCP callback establishes
the route and process identity.

Each native control uses the running stock handler's already generated payload,
wrapped through the existing Framework ELF helper. ELF class and machine fields
must match x64 or x86. The exact executable then passes through the actual Rex
printf or Bourne command-stager implementation, independently of module delivery.
The copied script's checksum and bytes are checked before execution as UID 33.
Native success therefore establishes architecture, decoder and session readiness;
a failed control would withhold the corresponding owner verdict.

Both native x86 controls succeed on this Docker host. This result comes from
executing the actual 32-bit payloads, rather than inferring support from an image
platform or architecture label. Runtime payload-gem versions are retained.

## Actual execution and cleanup

| Profile | Architecture | Stager | Examples | Used/closed sessions | Functional time |
| --- | --- | --- | --- | --- | --- |
| `opendcim_dropper_x64` | x64 | printf | 3 | 3 | 147.45 s |
| `opendcim_dropper_x64_bourne` | x64 | Bourne/base64 | 3 | 3 | 159.42 s |
| `opendcim_dropper_x86` | x86 | printf | 3 | 3 | 139.12 s |
| `opendcim_dropper_x86_bourne` | x86 | Bourne/base64 | 3 | 3 | 126.67 s |

Times exclude service startup. Each profile has one native application/callback
case, one independent native stager/session case, and one actual owner case with
two executions. The first owner execution enables AutoCheck; the repeat disables
it and retains the same selected module. The real three-delay SQL check returns
its reason-bearing Vulnerable result. Each pair uses distinct backup tables.

The first x64 run observes automatic payload selection after switching to target
1; x86 is selected explicitly. The first printf run observes default stager
selection; the repeat selects printf explicitly. Bourne is selected explicitly.
Normal `MeterpreterTryToFork=false` and HttpClient timeout settings remain in
effect. A fresh UID-33 directory is supplied through `CMDSTAGER::TEMP`.

Passive traces retain actual executable/stager returns, source locations and
module SQL/HTTP activity. Physical executables must exactly match the generated
bytes and UID 33; Bourne's base64 file is checked as well. Every command reaching
`poison_dot` must match the generated stager command plus the module's appended
comment, byte-for-byte.

Every native and owner session uses public Meterpreter APIs to report PID and
identity and write the exact `opendcim-session` proof. Independent target reads
verify its physical bytes/UID and the PID/birth identity. The session responds to
a fresh PID request before graceful shutdown. The exact PID/birth pair disappears,
callback connections close, Framework jobs/sessions empty and the original SQL
reporting row acquires its closure time.

The ordinary foreground stager removes its executable and encoded file after the
payload exits. Physical absence and an empty delivery directory are required
while the containers still run, before fixture cleanup removes the empty
directory. Fixture removal does not delete the stager files to satisfy that
assertion. Apache's existing narrow prefork-worker exception is retained; all
other process identities must return to baseline.

All full configuration rows, seeded LDAP values, table names and source
fingerprints preserve after each session. Original factory values restore at the
end. All four first functional frames pass; no new module or harness failure is
observed in this tranche.

## Verification and remaining scope

The latest retained set has **93 cases / 28 profiles**, **43 used/closed OS
sessions**, **291 current declared input fingerprints** and **200 zero resource
event captures**. Historical coverage reaches **325 owners in stated paths,
698 profiles and 4,868 functional cases**. These are covered paths, not complete
qualification of every behavior in those modules. The static inventory remains
5,179 source files, 330 registered sources, 42 current reviews, zero stale reviews
and 167 pending exploit candidates with container hints.

The seven new Ruby files pass RuboCop with zero offenses. Module-document tidy
passes, and the human-written Scenarios section remains byte-for-byte unchanged.
Default dry-run discovery excludes all new Docker examples; its seven remaining
examples come from the existing acceptance datastore-formatting support spec.
Resolved Compose configuration and actual startup pass for all four profiles.
No full unit suite is run for this fixture addition.

Stacks run serially with at most three capped services: openDCIM at 768 MiB /
0.8 CPU, MariaDB at 384 MiB / 0.4 CPU and reporting PostgreSQL at 128 MiB / 0.2
CPU, with equal memory/swap limits and bounded PIDs. All **16 new / 560 recorded
Docker objects** independently verify absent. Both local contexts finish with
zero running/stopped containers and no owned ephemeral networks/volumes. No
agent or Docker-backed connector is initialized here.

HTTP authentication, other releases and patched-release behavior remain
unqualified. Target-0 default fetch still lacks curl/wget in the stock image.
These dropper profiles use an explicit writable directory. Ordinary unit CI
does not run these opt-in Docker profiles; published-head CI status is separate.

## Self-review

| Area | Assessment |
| --- | --- |
| Summary | Four native-gated profiles cover both dropper architectures and stager flavors. |
| What looks good | Real native stagers, exact physical payload bytes, public Meterpreter use, original SQL closure, normal cleanup and same-selection repeats. |
| Concerns | Auth/release variants and target-0 default fetch remain unqualified; the temporary directory is explicitly configured. |
| Suggestions | Qualify useful auth/check-failure paths next and continue the full module inventory. |
