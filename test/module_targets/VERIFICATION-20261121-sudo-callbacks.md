# Sudo default root callback verification

Observed 2026-11-21. The [callback profiles](sudo_chroot_sessions/README.md)
qualify actual default staged Meterpreter delivery from both declared entry APIs.
The [finite-command profiles](sudo_chroot/README.md) also replay against the
constructor repair. The full valuable feasible-module inventory goal stays active.

## Independent native and actual owning paths

The existing checksum-verified sudo1.9.16p2/1.9.17p1 builds and pinned Ubuntu24.04
are unchanged. One UID1001 target uses128MiB RAM/swap,0.5CPU,64PIDs, read-only
root and bounded tmpfs. No privileged mode, added capability, Docker socket or
published service port is used. Genuine compiler/direct-loader, ordinary sudo
denial, benign NSS denial, affected root nonce proofs and fixed denials precede
owning calls, as documented in the [earlier verification](VERIFICATION-20261121-sudo-chroot.md).

Real shell and Meterpreter entry sessions each receive two independent native
callback controls. The actual default HTTP fetch/staged Meterpreter producer and
handler run as UID1001 with explicit `/tmp` and genuine default `./` destinations.
The relative control launches from writable `/tmp`. Public APIs and physical
file UID/bytes, process cwd and executable UID/SHA256/ELF bytes qualify delivery.
The `/proc` observer adopts the observed process credentials for protected link
reads; no extra ptrace capability or payload change is used.

A cold original module selection chooses
`cmd/linux/http/x64/meterpreter/reverse_tcp` with `AllowNoCleanup=false`. The
owner's payload is never explicitly selected. Affected calls repeat on one
selection with AutoCheck on, then off; fixed controls retain AutoCheck twice
and refuse before both exploit bodies. Captured check events require the actual
reason-bearing result, or no check when explicitly disabled. Captured supplied
wrapper bytes prove `/tmp/filename` and default `./filename` destinations without
regenerating or replacing the payload. Both real entry APIs follow these paths.

Each affected callback must write exact physical UID0 bytes, provide working
getwd/relative-directory APIs, retain a physical cwd equal to `/tmp`, and close
gracefully with PID disappearance. The entry cwd remains independently
`/home/lab`. Complete selected configuration/foreign files, module artifacts and
final idle processes/sockets must preserve after the recorded payload reset.

## Confirmed module defect and source repair

The earlier entry-session fix keeps the caller outside staging, but the NSS
constructor still execs the payload from staging. The original default callbacks
successfully become root, then inherit a cwd which FileDropper deletes. All four
root callbacks across shell/Meterpreter entries show physical `(deleted)` paths
and public `getwd` error2; both AutoCheck settings reproduce it. The independently
delivered native payload retains a valid cwd. Real root execution and preserved
entry state do not qualify the broken new-session lifecycle.

Commit `19942e23e7de59748b5be4622048163376da0554` adds two C lines: a comment and
`chdir("..")` before `execve`. Staging is an immediate child of `WritableDir`, so
the payload returns to that existing writable parent without interpolating a
configured path into C. This preserves default relative fetch and avoids a
deleted callback cwd. The earlier persistent-entry/absolute-cleanup repair stays
intact. A proposed `/` destination is retained privately but never native-qualified;
source inspection showed it would redirect default relative fetch into filesystem
root. Metadata, payload defaults, checks and error guards remain unchanged.

| Profile | Original examples/failures/pending | Current repaired | Repaired seconds |
|---|---:|---:|---:|
| `sudo_chroot_sessions` | 4/2/0 | 4/0/0 | 159.17 |
| `sudo_chroot_sessions_fixed` | 4/0/0 | 4/0/0 | 135.03 |
| Existing `sudo_chroot` | Previously qualified | 4/0/0 | 119.32 |
| Existing `sudo_chroot_fixed` | Previously qualified | 4/0/0 | 93.80 |

The current **16/0/0** combines the final callback replay with the two finite
profiles from the earlier candidate wrapper; their declared relevant inputs
remain unchanged and match current files. Each current profile has zero outside
errors and successful cleanup. Native journal/image identity and input digests
bind both revisions to the exact same module SHA256
`a6485d69dc16ad73ffe8133b3f77d6e5caedf23e2ff77ca7e06b6c547e8a9020`.

Default `FETCH_DELETE=false` intentionally retains the fetched executable under
the repaired writable parent. Its physical bytes/hash/UID are captured and the
known absent-before file is explicitly removed. This is payload lab reset,
separate from automatic wrapper/NSS cleanup. The original relative executable
inside staging could already be unlinked; `/proc/PID/exe` retains its physical
bytes and deleted-path evidence. The test does not require an artifact to remain
when automatic cleanup legitimately removes it. Entry fixture reset occurs only
after assertions. Finite commands retain their separately documented
`AllowNoCleanup=true` opt-in. Reporting-database persistence is not claimed.

## Harness findings and focused regressions

The first attempt reaches genuine UID1001 callbacks but its root-credential
observer cannot read their protected cwd links. Owning bodies are withheld.
Matching observer UID/GID corrects that setup fault. A deliberately interrupted
fixed frame stays partial; no complete summary is invented.

The first candidate callback frame still reports4/2 because the recorder writes
new callback cwd into the entry cwd field. Physical cwd/getwd/relative APIs
already pass at `/tmp`; the final assertion incorrectly compares that value
with `/home/lab`. The corrected recorder preserves distinct fields and requires
both API and physical callback paths to agree with the expected directory.
Actual original deleted-cwd packets remain rejected. Thus similar4/2 totals
have different setup, module and recording causes; raw attempts remain separate.

Frozen recorded-field regressions improve **9/1 to9/0**: two focused cases and
seven repeated eager support examples. The fixture uses real current and original
captures, with only a nonoperational16-byte ELF header. Separately, actual native
control and shutdown errors expose a first-error masking problem. Identical
focused cleanup tests improve **9/2 to9/0**; cleanup now retains the first error
and records secondary transport/assertion errors. Observer layout correction is
AST-equivalent. These unit controls explicitly double remote APIs.

The unchanged existing source tests remain **36 focused plus7 support, all
passing**, before and after the constructor change. They double compilation and
transport and do not validate C execution. The parent's final combined suite is
**64/0**:36 source,5 original state,2 callback cleanup,2 recorded state,12 PHP
lifecycle and7 support examples. Counts overlap the individual runs.

## CI fixture isolation

The previous published head's [Verify run](https://github.com/dwelch-r7/metasploit-framework/actions/runs/44958448530)
gets past the earlier startup error; its Ruby3.4 non-content job reports21,366 examples,
two failures and667 pending. Only two lifecycle content-control tests fail;
the retry reports9/2 including7 support repeats. The standalone child fixture
inherits parent `SPEC_OPTS=--tag ~content`, which excludes its own content example.

The fixture now clears that variable before loading RSpec. Parent selectors,
all unit assertions, production acceptance hooks and payload source remain
unchanged. Frozen inherited-selector tests improve **12/2 to12/0** on Ruby3.3.13
and Ruby3.4.5; scoped rake passes12/0 and production dry-run still registers8
examples. Ruby3.4 uses an explicitly isolated existing RSpec bootstrap because
its full locked Framework bundle is incomplete; no dependencies are installed.
The parent independently passes12/0 with the inherited selector on Ruby3.3.13.
Full remote CI success and fresh ProjectSend native qualification remain pending.

## Evidence, cleanup and limits

Private raw evidence is under `tmp/sudo-callback-feasibility/`. Retained wrappers
are `functional-20261121T225238`, `225544`, `230510`, `231454` and `232900` under
`tmp/invoiceshelf-feasibility/`. The first candidate's finite runtimes are under
`tmp/module-target-tests/20261121T231456-67852c/`; final callbacks are under
`20261121T232902-f0c8b9/`. All runtime inputs remain unchanged within each frame;
separately diagnosed harness and CI updates are explicitly rebound in the audit.

The passing set reaches **192 cases /47 profiles /540 retained current inputs**.
Across retained attempts, **68 additional sessions** are used and closed,
including16 original owning callbacks:177 ordinary sessions total, with21 PHP
source-variant sessions retained separately. Finite commands and native NSS
constructor proofs are not counted as OS sessions. Registration is not a pass.

All **24 new /861 recorded Docker objects** are independently absent. Both
contexts include stopped containers and are globally empty;163 recorded host
callback/fetch ports are closed and no console/guard remains. This step's target
and global peak is one. Both reused agents create zero resources. Every completed
stack is removed immediately; no images/caches are pruned or daemon settings
changed. The shared lifecycle rule covers namespaces, exact IDs, startup helpers
and cleanup on all exits.

Scoped Ruby lint/source tidy and documentation checks are recorded separately;
two inherited module-doc line4 warnings remain and human Scenarios preserve.
Other payload families, architectures/writable paths, compiler-denial recovery,
distro/backport/release boundaries and reporting databases remain unqualified.
Other valuable feasible owners and earlier failures remain in scope. No PR or
external comment is created.
