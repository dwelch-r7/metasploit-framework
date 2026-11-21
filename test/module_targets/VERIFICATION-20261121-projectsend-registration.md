# ProjectSend registration repair and partial option prevention

Date: 2026-11-21. The repaired module registers valid generated clients and
reports creation only after verified login. Actual command and explicit
candidate-source session paths work on pinned r1605-ls199. Five unintended option
mutations are prevented; strict preservation still fails for deletion permission.
This is a **partial repair**, not full module or installed-payload qualification.

## Reproduction and source changes

Run the existing recipes serially with the shared guard and a task namespace:

```sh
MODULE_TARGET_NAMESPACE=projectsend-local bundle exec ruby tools/dev/run_guarded_module_target_tests.rb projectsend projectsend_rce projectsend_sessions_candidate
```

The last profile is an explicit PHP source comparison. Its supported disposable
override does not qualify the installed payload bundle; see the
[comparison recipe](php_meterpreter_source/README.md). The ordinary
`projectsend_sessions` profile is tested separately without that override.

Two fixes were prepared and committed in a separate worktree, reviewed, and
cherry-picked before parent native replay:

- Registration: constrain Faker usernames to the backend character/length
  requirements; normalize retained hyphens/underscores to dots. Accept real
  302/303 redirects to the expected client portal for login, and print creation
  success after the existing upload login succeeds. A cookie or registration
  HTTP 500 alone does not establish success. No login request is added.
- Partial prevention: route client-option writes through the checkbox-free
  branding section, omit POST `section`, and stop writing the unnecessary upload
  permission and expired-file visibility. Keep the original security-section
  checkbox behavior and cleanup deletion capability. Do not invent original
  option values or use privileged fixture SQL in production code.

Current module SHA256:
`2eba08bfb82a3ebcdca20aec942fef618e2edbdae9f1937529e69e599181f736`.
The registration-only intermediate was
`ab2a11e048996f5c89afb339c9b35f83568004ac5c75bbabd9d256ed8fd2ff5f`;
the previous module was
`6eb96c4110fa0a780948ebe196fbc14569766dfb88e63a093e8301ff471a3ce9`.
Functional harness files and preservation expectations are unchanged.

## Actual native results

Counts are examples/failures/pending. Each profile uses a fresh isolated stack.

| Source/frame | Profile | Result | Seconds | Observed outcome |
| --- | --- | --- | ---: | --- |
| Registration repair | Check | 3/0/0 | 55.02 | Original checks and exact recovery pass |
| Registration repair | PHP command | 3/1/0 | 64.27 | Two exact command proofs; six option mutations retained |
| Registration repair | Ordinary installed PHP | 4/2/0 | 356.38 | Two native sessions work; first owner times out; one outside-example error |
| Registration repair | Explicit candidate PHP | 4/1/0 | 130.55 | Four used/closed sessions; six option mutations retained |
| Partial prevention | Check | 3/0/0 | 49.10 | Checks and recovery still pass |
| Partial prevention | PHP command | 3/1/0 | 63.70 | Two exact command proofs; only deletion permission changes |
| Partial prevention | Explicit candidate PHP | 4/1/0 | 124.53 | Four used/closed sessions; only deletion permission changes |

Independent application installation, PHP generation/execution, real
registration/login, denied/allowed uploads and physical/portal cleanup precede
owner verdicts. All eight completed owning calls across both repairs generate
backend-valid usernames and actual active level-zero SQL accounts. Each has one
login before upload and another existing cleanup login. Creation output follows
the first successful login. Native SQL is an independent observer, not an exploit
primitive supplied to the module.

Four actual owning `php/exec` commands prove exact UID1000 bytes, including the
quoted Unicode/CRLF case. Eight candidate-source sessions prove real native
CLI/web and default-target owner use, remote UID/bytes, process identity and
callback closure, plus original reporting-row closure. Both candidate frames
use one selected module with AutoCheck on/off. Actual source reads match the
reviewed candidate, debug build stays false, debug logging stays unset, and each
override is removed. The installed 2.0.257 payload gem and full manifest remain
unchanged; no repository payload fallback is present.

After partial prevention, all **134** option rows remain after each completed
owner. Five previously changed/added names preserve:
`clients_can_set_expiration_date`, `clients_can_upload`,
`clients_new_default_can_set_public`, `expired_files_hide`, and `section`.
`clients_can_delete_own_files` still changes **1 to 0**. The complete preservation
example remains failing, and created clients remain. Subsequent fixture recovery
and stack deletion do not count as successful module cleanup.

## Important unresolved observations

The ordinary installed-bundle frame is not merely an early bootstrap failure:
both native CLI/web sessions were used and closed this time. Its first owner
requested the actual uploaded path and the PHP file self-unlinked, but no owner
session became ready. The foreground console timeout caused a dependent failure
and an outside-example cleanup error. The frame and final artifact state are
retained. Timeout recovery needs hardening; increasing passing counts or weakening
the session expectation would not resolve it. The exact original wire failure
was not captured, so the known PHP framing defect is not asserted as the proven
cause of this particular timeout. The current partial source has no qualified
ordinary installed-bundle owner session.

Exact restoration of original registration/security settings also remains
unresolved. The unauthenticated interface does not supply a general settings
snapshot; fixed cleanup values cannot preserve every possible operator value.
The partial repair retains existing security and deletion behavior rather than
reducing cleanup capability to make a test pass.

Pinned r1295-ls89 image source was copied from its real `/app/projectsend-tmp`
tree without starting the image. The first source-location guess failed and its
stopped container was removed; image history supplied the correct path. The
second extraction records 409 PHP hashes. Upload, bootstrap/session, CSRF and
Files paths support the narrower source conclusion that the direct upload API
does not enforce `clients_can_upload`; branding has no checkbox reset list.
This is **static compatibility evidence only**. r1295 authentication/runtime and
disabled-upload-zero native execution remain unqualified.

## Validation and cleanup

Identical worker inputs reproduce registration **51/11 to 51/0**, then partial
prevention **61/9 to 61/0**. Parent independently passes 51 and then 61 examples;
the latter comprises 54 owner cases and seven Framework support examples.
One inherited default-PAYLOAD lint/tidy warning remains, verified against the
original source. No new offenses are introduced. Module docs, syntax, whitespace
and current input hashes verify; the **926-byte** human Scenarios tail is unchanged.

All **68** before/after cgroup captures have zero OOM/PID-limit events and no
counter growth. Some baseline memory.max counters are nonzero and unchanged;
these are not reported as zero-pressure captures. Serial stacks use at most
three running services, **768 MiB / 1.2 CPUs**. Both source-only containers were
never started. All **26 new / 735 recorded Docker objects** are absent, both
contexts include no stopped/running containers, and callback ports are closed.

The fully passing case/profile set stays **132 / 37** with **412** current
declared inputs. Retained ordinary native/owner sessions reach **49**, including
the two new native controls; source-variant sessions are separate, **eight new /
17 retained**. No ordinary stock owner session is added. Raw frames, units,
source inspection, integrity checks and cleanup receipts are sealed locally via
the continuation checkpoint. No PR is created; the full inventory goal stays active.
