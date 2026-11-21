# Sudo chroot local-owner and preservation verification

Observed 2026-11-21. The [affected profile](sudo_chroot/README.md) and
[fixed control](sudo_chroot_fixed/README.md) qualify finite root commands from
real shell and Meterpreter entry sessions. The full valuable feasible-module
goal remains active; default/new root callback sessions remain unqualified.

## Genuine prerequisites and original entry points

Official checksum-verified sudo 1.9.16p2 and 1.9.17p1 archives build on pinned
Ubuntu 24.04. One target runs at a time as UID1001 with 128 MiB RAM/swap,
0.5 CPU, 64 PIDs, read-only root and bounded tmpfs. There is no privileged flag,
added capability, host Docker socket or published service port. Package and
binary identity are retained. The [upstream fixed release](https://github.com/sudo-project/sudo/releases/tag/v1.9.17p1)
and [researcher's NSS mechanism](https://www.stratascale.com/resource/cve-2025-32463-sudo-chroot-elevation-of-privilege/)
supply provenance; actual compiled binaries establish behavior.

Before the module runs, native controls prove ordinary sudo denial, successful
unprivileged shared-library compilation/loading, inability of that direct loader
to become root, and benign NSS denial. Two actual malicious NSS constructor runs
produce exact nonce-bearing UID0 proof files on the affected build; the fixed
build denies both. Original selected system/foreign files preserve and the native
tree is removed. Memory/OOM/PID events remain zero.

Unmodified Framework Linux x64 payloads establish real shell and Meterpreter
entry sessions. Public session APIs, exact physical UID1001 bytes and PID/birth
identity gate owning calls. Independent real HTTP fetch/exec controls first
produce each quoted Unicode/backslash/CRLF command's exact bytes as UID1001.
The same selected original local module then performs two checks and two
AutoCheck root commands per entry API. Passive tracing records original calls
and reason-bearing results. Affected commands must write the exact bytes as
UID0; fixed AutoCheck must refuse without entering the exploit body.

## Confirmed defect and repaired native results

The original module changes its caller's persistent cwd to the staging tree.
Existing `Post::File#mkdir` already registers that tree for cleanup: the initial
suspicion of missing registration was disproved. Cleanup correctly deletes it,
leaving the original session inside a removed directory. Shell reports a stale
cwd; Meterpreter `getwd` raises error2 and the second owner run cannot proceed.
Physical UID0 command proofs already succeed before this preservation failure.

The repair uses absolute staging paths and a command-local, shell-escaped `cd`.
The persistent caller never changes cwd. Only the absolute parent is registered;
its recursive cleanup owns nested directories. Focused regressions protect
foreign home paths from relative cleanup entries. Existing guards, metadata,
payload selection and version checks are unchanged.

| Profile | Corrected original examples/failures/pending | Repaired | Repaired seconds |
|---|---:|---:|---:|
| `sudo_chroot` | 4/2/0 | 4/0/0 | 148.42 |
| `sudo_chroot_fixed` | 4/0/0 | 4/0/0 | 84.27 |

The corrected original affected replay separately retains **4/2/0**, with direct
proofs after structured cwd observation. All complete frames have zero outside
errors. The repaired **8/0/0** matrix preserves the original cwd, entry identity,
all selected config/foreign hashes, module wrapper/NSS artifacts and final idle
process/socket state, and repeats successfully on each selection.

Finite `cmd/linux/http/x64/exec` commands explicitly require
`AllowNoCleanup=true`; the normal Framework guard otherwise refuses them before
AutoCheck. Default `FETCH_DELETE=false` intentionally retains the fetched ELF.
Its exact UID/hash/bytes are captured and that absent-before file is explicitly
removed as lab reset. This is distinct from automatic module wrapper/NSS cleanup.
After assertions, fixture reset restores cwd, gracefully closes entry sessions
and removes the completely captured new `/tmp` tree. None of that reset is
counted as module cleanup. Reporting-database persistence is not claimed.

## Focused regressions and separate harness findings

Identical source-unit inputs improve **43 examples/26 failures to 43/0**:
36 focused cases plus seven eager support examples. They exercise the real
exploit, Post::File and FileDropper methods with explicit session/compiler/
transport/filesystem doubles; native execution is established by the profiles.
Both entry APIs, early guards, failure returns, expected/unexpected exceptions,
repeat/cleanup, foreign-path safety and shell quoting are covered.

Five harness regressions plus seven eager support examples improve **12/2 to
12/0**. A captured kernel TIME_WAIT record has inode0 and owns no live socket;
raw journals retain it while the comparable state excludes only that exact
kernel condition. Established, half-closed and unexpected nonzero-inode records
still fail leak criteria. Cleanup also preserves the first operation error.

Earlier attempts separately retain: UID1000 already occupied in the base image;
an incorrect setuid-mode assertion; read-only-root `docker cp` refusal; an
incompatible generic command payload; finite-handler lifecycle misuse; and an
omitted `AllowNoCleanup` prerequisite. Independent real producer calibration
corrects the harness without replacing module methods. The first Meterpreter
cwd probe also cascaded into a nil parser error; structured observation preserves
the original API error and physical root evidence. Two deliberately interrupted
frames remain partial and supply no invented complete RSpec summary.

## CI source-hook correction

The previous published head's [Verify run](https://github.com/dwelch-r7/metasploit-framework/actions/runs/44951923754)
failed during content-spec discovery because an unrelated global PHP-source
`before(:suite)` hook required a lab runtime despite acceptance being excluded.
This predates the Sudo change. The hook now prepares within its selected source
acceptance context before console startup and cleans up after console shutdown.
Stock and source groups share unchanged native examples. All three manifests
hash the new helper. Module and payload-source candidate bytes are unchanged.

Identical isolated lifecycle regressions improve **12/2 to 12/0**. Actual scoped
`rspec-rerun:spec` content startup now exits0; its seven passing examples are
eager support repeats, with zero native/source examples executed. Actual dry-run
registers all eight stock/source examples, and missing-runtime acceptance still
fails closed. These checks do not requalify ProjectSend native behavior or fix
its previously retained preservation defects. The parent's combined focused
suite passes **60/0**: 36 source, five harness, twelve lifecycle and seven support
examples. Counts overlap the separate runs above.

## Evidence, cleanup and remaining work

Private evidence is under `tmp/sudo-chroot-feasibility/`. Seven retained wrappers
span `functional-20261121T214920` through `functional-20261121T223203` under
`tmp/invoiceshelf-feasibility/`. Final runtime is
`tmp/module-target-tests/20261121T223205-31524a/`, revision
`f0770a78bbcd9c72ebb1d16372d0209886acd5fa`, with source SHA256
`8b767bdc29e02b10f70656733998d769762a3777df3e4ec02c36020dcceabad4`.
All runtime input hashes preserve; committed-blob verification binds publication.

The passing set reaches **184 cases / 45 profiles / 523 current retained inputs**.
Seventeen additional entry sessions are used and closed across retained attempts,
bringing ordinary sessions to109; the 21 separate PHP-source sessions stay
separate. Finite commands and native constructors are not counted as OS sessions.
Registration and input retention alone do not prove a module/path passes.

All **31 new / 837 recorded Docker objects** are absent. Both contexts include
stopped containers and are globally empty. The target peak is one; two unused
automatic agent-startup helpers briefly make the global peak three. Both helpers
are identified, namespaced and removed immediately. Recorded callback/fetch
listeners are closed and no local console/guard remains. No images or caches
are pruned, and daemon settings are unchanged. The shared lifecycle policy requires every agent
to namespace, track and clean resources on all exits, including tool helpers.

All eleven changed Ruby files pass scoped lint and the changed module passes
msftidy. Module-doc tidy retains two inherited line4 warnings (trailing space
and length); no new warning is introduced. All 1,477 human Scenario bytes are
unchanged. Full-suite and remote CI success are not inferred from targeted
local checks.

Default/new root callback sessions, AutoCheck disabled, compiler-denial recovery,
alternate payloads/writable paths and distro/backport/version boundaries remain
open. A new root session could have different cwd/lifetime behavior from the
original entry session; that requires real testing. Other valuable feasible
owners and earlier failures remain in scope. No PR or external comment is made.
