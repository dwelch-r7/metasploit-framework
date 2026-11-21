# PHP Meterpreter source comparison and ProjectSend registration

Date: 2026-11-21. These results retain failures; they do **not** qualify the
ordinary installed PHP payload bundle or complete the module inventory goal.
ProjectSend production source remains SHA256
`6eb96c4110fa0a780948ebe196fbc14569766dfb88e63a093e8301ff471a3ce9`.

## Reproduction and boundaries

The [source comparison recipe](php_meterpreter_source/README.md) reuses the
original four ProjectSend session examples with a supported, isolated
configuration-directory payload override. Run the guarded command there for
`projectsend_sessions_control projectsend_sessions_candidate`. Run
`projectsend_sessions` separately for the ordinary installed gem. All profiles
remain enabled with their strict success and preservation expectations.

The control is the unmodified decrypted source from installed
`metasploit-payloads` 2.0.257, SHA256
`e031bea39090ccc1c3086474c971c00368006e9105aa198d783f94225b36740d`.
The included source patch reconstructs candidate SHA256
`e17550cce49a90f2a0922242b8697095d35d2c689df0ef3916fb4f104c23f7a1`.
It changes TCP frame buffering/retirement, leaving generic read behavior alone.
Its payload-repository commit is local and has not been published. The prior
native PHP framing comparison had 20 tests: original 13 failures, candidate zero.

Both comparison modes check the complete installed gem manifest before and
after execution, verify the actual Framework reader path/source digest, and
remove the exact disposable override. Passive observations capture the original
stage generator and library reader; debug build remains false and debug logging
unset. The installed encrypted PHP file remains SHA256
`655670e3432f0d705e4eb3ab97aa157d3340d142cfb50788fa7a95ff4b05101c`.
No owner, handler or generator method is replaced. Observations can affect timing;
these are source comparisons, not ordinary-bundle qualification. The original
historical failing bootstrap wire was not captured, so its exact cause remains
unproven.

## Actual results

Counts are examples/failures/pending. Each row is a separate fresh stack.

| Frame | Result | Seconds | Fully used/closed sessions | Verdict |
| --- | --- | ---: | ---: | --- |
| First private candidate | 4/2/0 | 110.94 | 2 | Native CLI/web work; harness incorrectly rejects unset raw TARGET |
| Corrected private candidate | 4/1/0 | 135.82 | 4 | Native CLI/web and both default owner calls work; preservation fails |
| Matched private original source | 4/1/2 | — | 0 | Native CLI bootstrap fails; owners withheld |
| Ordinary installed bundle | 4/1/2 | 110.07 | 0 | Native CLI bootstrap fails without source override or source observer |
| Maintained original-source control | 4/1/2 | 122.94 | 0 | Native CLI bootstrap fails; override removed and gem unchanged |
| Maintained candidate | 4/2/0 | 101.14 | 3 | Native CLI/web and first owner work; second registration creates no account |

The harness correction observes `target_index == 0`, the effective PHP Command
target, instead of rejecting a legitimately unset raw `datastore['TARGET']`.
Neither target nor payload is forced. The two owners use one selected module,
default `php/meterpreter/reverse_tcp`, and AutoCheck on/off. Real sessions prove
UID1000, exact physical bytes, process identity/birth, callback socket-inode
closure and original reporting SQL row closure. Persistent FPM workers are
distinguished from live callback ownership.

The corrected private frame reaches both owners and retains the established six
option changes: `clients_can_delete_own_files`,
`clients_can_set_expiration_date`, `clients_can_upload`,
`clients_new_default_can_set_public`, `expired_files_hide`, and `section`.
Fixture recovery happens after capturing these changes and does not count as
successful module cleanup.

The final maintained candidate's second owner generates an underscore username.
The original registration POST returns 303 to `register.php`, creates no account,
and is followed by a login failure, despite the module printing that the user
was created. Its second failing example is the dependent owner-completion
assertion; it does not independently establish another two-owner preservation
result. Generated data is retained; it is not replaced to obtain a green run.

## Native registration counterfactual

The [native registration control](projectsend_registration/README.md) invokes no
module and verifies the pinned original `Users.php` and `Validation.php` hashes.
The original backend validator rejects the captured underscore username and
accepts the same username with underscores replaced by dots. All other captured
registration fields stay identical, with a fresh real CSRF token for each POST.

The underscore case returns 303 back to registration with zero SQL rows. The
dotted case persists one active level-zero account; genuine credential login
then returns 303 to `my_files/index.php`. Registration itself returns HTTP 500
after persistence. That application error is retained separately and its exact
cause is unresolved. It does not erase the SQL/login evidence or demonstrate a
successful registration response. A first control stopped prematurely at that
500; the corrected control checks actual persistence and authentication, captures
available logs, and restores the options/users/files/physical snapshot.

This confirms two module issues for further investigation: unconstrained Faker
usernames can violate the backend's accepted character set, and registration
can print success without establishing that an account exists. No production
module fix is included here. The existing preservation failure also remains.

## Accounting and cleanup

The fully passing ordinary set remains **117 cases / 34 profiles / 47 used and
closed sessions**. The current input ledger verifies **394 declared inputs**;
only the intentional two-line target-selection observation refreshes an older
input hash. The **nine** fully used/closed candidate-source sessions across the
three frames are diagnostic results, separate from those ordinary totals.

Profiles run serially with at most three capped services, **768 MiB / 1.2 CPUs**.
Both native registration controls use two services, **640 MiB / 1 CPU**. All
**30 new / 694 recorded Docker objects** are independently absent, and both
Docker contexts are globally empty, including stopped containers. No image,
cache, shared volume or daemon pruning is performed. No PR is created.

Raw result/input manifests, failed frames, actual source events, native SQL/HTTP
controls, full integrity checks and cleanup receipts are retained in the local
evidence capsule referenced by the continuation checkpoint. Broader release,
payload, target and module coverage remains active.
