# LinuxKI sessions and retained repeat failure — 2026-11-22

Two profiles qualify **8 examples /zero failures /zero pending**. A third enabled
profile retains an unresolved repeated-session failure. The full valuable
feasible-module goal remains active. Production and installed payload source
are unchanged in this milestone.

| Profile | Final result | Observed scope |
| --- | --- | --- |
| `linuxki_sessions` | 4/0/0 | Stock Bash CLI/page controls; explicit Bash target2; two owning sessions on the same selection with distinct ports |
| `linuxki_php_sessions` | 4/0/0 | Repeated stock PHP CLI/page controls; untouched initial TARGET/PAYLOAD; two owning PHP Meterpreter sessions on the same selection |
| `linuxki_unix_default_sessions` | 4/1/0, plus1 outside-example baseline error | Repeated native command-wrapped PHP controls and first owner proved; second owning bootstrap does not reach readiness/use |

Run serially from the Framework root:

```sh
MODULE_TARGET_NAMESPACE=my-linuxki-sessions bundle exec ruby tools/dev/run_guarded_module_target_tests.rb linuxki_sessions linuxki_php_sessions linuxki_unix_default_sessions
```

The command intentionally includes the retained failing profile. It returns
failure while that repeat remains unresolved. The two qualified profiles may
also be selected independently.

## Independent prerequisites and session proof

The target reuses the checksum-pinned genuine LinuxKI6.0-1 DEB on Debian11/x64,
PHP7.4.33 and Apache. Actual CLI linkage/help, vendor page/binary hashes and
exact UID33 shell/HTTP command effects must pass. The existing PHP procfs
observer is mounted read-only; no interpreter or database is added.

A UID33 callback/ack exchange proves the route independently of any payload.
The stock handler's bound-listener message is required before launching its
already generated program. CLI and genuine-page payload controls precede owning
calls. Repeated PHP controls use different callback ports. No target, payload,
HTTP response or session producer is mocked.

For PHP, both `meterpreter.php` and `ext_server_stdapi.php` must resolve to
ordinary `metasploit-payloads 2.0.257` files matching the package manifest and its
digest. Resolved paths, raw/decoded hashes and decoded source bytes are retained.
Decoded SHA256 values are:

```text
meterpreter.php        e031bea39090ccc1c3086474c971c00368006e9105aa198d783f94225b36740d
ext_server_stdapi.php  f7cd2a58ee586e666bf414444a69eede9cd1308a3ac4054138822d7861b78402
```

The literal PHP native handler copies the real target0 single-quote bad character.
Its CLI passes the generated program as one PHP argument; its page control uses
the same `php -r` quoting envelope as the owner. Command-wrapped PHP instead uses
the actual generated shell command. No private framing/runtime candidate is
installed. A local source override fails readiness.

Every credited session requires the real ready event, expected owner/payload,
public identity/file-write APIs, exact physical proof bytes and UID33, and a
matching PID/birth record. A fresh public response precedes remote shutdown.
Remote PID disappearance is required before local deregistration; socket absence
is then checked. TIME_WAIT is excluded by the existing observer. A background
console message saying no session exists does not determine success.

The first owning run uses AutoCheck; the repeat disables it on the same selected
module and changes the callback port. Apache may add a legitimate spare prefork
worker under its original parent; other UID33 processes must return to baseline.
Proof/log files are removed. There is no reporting database and no database
persistence claim.

## Retained failures and investigation

The initial harness matched Docker init's command as an Apache parent. A later
observer stored baseline/port fields only on individual RSpec examples, and a
TCP check preceded closure of Framework's local socket. Captured procfs/socket
data identified these harness defects. Shared receipt state and the correct
remote-exit/local-close order repair them. Recovery records cleanup errors while
preserving the primary exception. All failed/interrupted stacks are removed.

The console selects `cmd/unix/php/meterpreter/reverse_tcp` after a plain module
selection followed by `set TARGET 2`. The initial Bash test wrongly expected the
metadata's Bash recommendation to remain selected. Its unproved callback is not
counted. Explicit Bash and the actual automatic Unix/PHP path are now separate
profiles; no Framework selection behavior is changed.

An earlier probe shortened native communication/expiration settings to8/90.
One such PHP run completed six sessions; a later replay repeatedly failed
bootstrap before any owning calls. Package, callback and listener gates passed.
These outcomes remain retained and their exact cause is unclassified. The final
profiles use ordinary native transport defaults. Current initial PHP passes;
this result does not close PHP failures in other application/runtime labs.

With ordinary defaults, the automatic Unix/PHP profile completes four native
sessions and one owning session. The second owner uses the same selected object
and a fresh4473 callback port, but never completes readiness/public use. A C2
connection remains during baseline recovery and the Framework reports invalid
Meterpreter bootstrap sessions. The profile records one failed example and one
outside-example baseline error. It stays enabled and is excluded from qualified
case/profile totals. The exact failure layer remains unclassified; independent
native success and a callback alone do not identify a LinuxKI source defect.

Next isolate fresh versus reused selection, AutoCheck state and same-instance
stock-handler repeats; retain the real initial encryption handshake with the
existing session TLV logging before making a source repair. PHP and Linux
x86/x64 dropper success paths and other release/platform/network paths also
remain open.

## Qualification, checks and cleanup

The final attempted matrix has12 examples, one failure, zero pending and one
outside-example error. Its two qualified profiles add8 cases and2 profiles.
Fifteen sessions in that final matrix and13 earlier sessions have complete
public/physical use-and-closure proofs: **28 new ordinary session lifecycles**.
Invalid bootstrap attempts and unproved callbacks are excluded.

The retained set reaches **353 cases /80 profiles /811 current inputs**, with
**355 ordinary actually used/closed sessions** and21 separate source variants.
All801 previous runtime inputs remain byte-identical. The failing profile has
its own frozen inputs and is not counted as a qualified profile.

Changed Ruby passes lint, and syntax/diff checks pass. Module-doc tidy retains
the same six inherited inline-backtick warnings with zero new findings. No
production module/library or installed payload file changes, new dependencies,
opaque binaries or generated human Scenarios are added.

Every stack peaks at two capped containers. Final profiles record zero
OOM/PID-limit events, including resource capture after the failed baseline check.
All **36 new /1,242 recorded container/network/volume IDs** are absent, both
Docker contexts are globally empty including stopped containers, and no new
global volume remains. No helper containers are initialized in this phase;
no image/cache pruning or daemon restart occurs.

Evidence is indexed under `tmp/linuxki-sessions-feasibility`: `QUALIFICATION.json`,
`COMBINED-QUALIFICATION.json`, `RETAINED-HARNESS-FAILURES.json`, `CLEANUP.json`
and the checkpoint/publication/seal receipts. The final wrapper is
`tmp/invoiceshelf-feasibility/functional-20261122T103241`, and its runtime is
`tmp/module-target-tests/20261122T103243-e830dd`. No PR was created.
