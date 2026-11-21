# ProjectSend check state preservation

The [ProjectSend profile](projectsend/README.md) passes **three examples / zero
failures / zero pending**, following native installation/PHP/API gates. The
original owner changes ten options during a standalone check and fails both
owning examples; the repaired source preserves all **134 option rows**, repeats
on one selection and handles a refused port without extra cleanup requests.
Only the module source differs between the original and final functional inputs.
The complete valuable/container-feasible inventory goal remains active; owning
RCE/session paths are still pending qualification.

## Native application and prerequisites

The unchanged publisher image is **LinuxServer r1605-ls199**, pinned by
architecture-specific digest in [vendor.json](projectsend/vendor.json). Its OCI
revision matches the [publisher Dockerfile](https://github.com/linuxserver/docker-projectsend/blob/8d5e199388efbaeba365e78926f34c1edcca9996/Dockerfile).
Twelve application files are independently fingerprinted. Actual runtimes are
**PHP 8.3.9** and **MariaDB 10.11.9**. The fixture writes ordinary database
configuration and uses the genuine HTTP installer, rather than importing a
fabricated database or replacing application code.

Native controls first run a self-removing PHP program from the real upload
directory. Its exact quoted Unicode/CRLF proof is owned by UID 1000. Independent
unauthenticated options requests change only the title, require matching database
and rendered UI state, then restore every option. The fixture seeds an ampersand/
Unicode title, custom footer, language/editor choices and client permissions.
Factory values and the configuration-file fingerprint recover afterward.

The pinned PHP build returns HTTP 500 after an unauthenticated options write has
already persisted. The complete backend/UI proof and recovery remain mandatory.
A separate temporary DEBUG configuration reveals an undefined CURRENT_USER_ID
error at options.php:229 after the write; its rendered fatal diagnostic returns
HTTP 200. The exact original configuration and all options restore before any
owning invocation. Normal DEBUG=false mode suppresses error reporting. No
application source or extension is changed to obtain a passing native control.

## Original faults and isolated repair

The original functional frame has **3 examples / 2 failures / 0 pending** after
a successful native gate. A real Appears check changes ten option names:

- Client upload, deletion and expiration permissions change from 1 to 0.
- Browser language, custom footer and editor flags change from 1 to 0.
- The saved title gains a literal encoded ampersand.
- Three option rows are added, including section=security.

Raw SQL state is captured before deliberate fixture recovery. The general-form
POST implicitly resets omitted checkboxes. Framework calls cleanup after a
standalone check, and the original cleanup unconditionally changes client and
security options. A refused-port check returns Unknown, then cleanup requests
the unavailable page again and raises a module failure.

The repair selects the checkbox-free branding section in the query and posts
only the token/title. It decodes DOM title text, verifies restoration, and
attempts recovery after ambiguous POST replies or verification failures.
Nullable responses return reason-bearing CheckCodes. Exploit cleanup is gated
on an actual attempt, retains parent cleanup and clears its per-attempt state.
Expected cleanup errors are reported without raising from cleanup. Payload
selection and the existing default remain unchanged.

The isolated initial fix improves identical focused inputs from **32/18 to
32/0** examples/failures. Parent review then calls the candidate's actual title
parser with the publisher formatter and confirms that strip removes legitimate
saved spaces. An expanded identical suite improves **34/1 to 34/0** after the
small follow-up; the final suite has **27 owner regressions and 7 shared-support
examples**. The parent independently reruns all 34 successfully. Whitespace,
entities, Unicode, missing title/CSRF, nullable replies, restoration failures,
standalone cleanup and per-attempt cleanup gating are covered. Historical r1294
and r1335 source support the selected API semantics; older-release runtimes,
including exact r1295, remain unqualified.

## Maintained candidate replay

The final source SHA256 is
`6eb96c4110fa0a780948ebe196fbc14569766dfb88e63a093e8301ff471a3ce9`.
The original module SHA256 is
`0b199c1b1f7791e4aa826e6aaff8c72d285c2e19ef08a7f49947aa6f65824bc0`.
All other original functional input fingerprints match. The final **3/0/0**
frame takes **52.87 seconds**, excluding startup. Both actual Appears checks
preserve all 134 rows and the raw saved title on one console selection. The
native refused-port case emits Unknown, performs exactly one GET and has no
extra cleanup error. No exploit body runs in this profile. Full factory options,
configuration bytes and the application fingerprints recover.

Ruby syntax passes. Five changed/new Ruby files have one inherited default-
PAYLOAD warning; the same warning keeps msftidy at exit 2 and RuboCop at exit 1.
There are **zero new offenses**. Module-document tidy and default test discovery
pass, and existing human-written Scenarios bytes are unchanged. The Docker
profile remains opt-in; no full unit suite is run. Published-head CI is observed
separately from these local results. No PR is created.

## Independent RCE readiness and remaining scope

A separate native control completes real unauthenticated client registration,
explicit login and genuine multipart upload. PHP is specifically denied while
the extension whitelist applies, with HTTP 400 and the application's Invalid
Extension result. With the appropriate real option changed, upload returns
HTTP 200/OK and a genuine database row. Exact physical PHP bytes execute as UID
1000, write the expected proof, self-unlink and are removed from the portal's
original file row. All options restore. Registration itself returns HTTP 500
after creating the account; its post-creation error cause remains unclassified.
The authenticated login and subsequent upload/execution prove usable state.

The first cross-client upload control fails because Python's exported session
cookie has an empty expiry field and curl starts a new unauthenticated session.
The corrected transport uses CookieJar's resolved Cookie header, verifies the
client UI first and passes the full control. Both frames are retained. These
controls establish the real primitive; **actual owning RCE, default PHP sessions,
created-account handling, exploit cleanup/configuration preservation and other
releases remain pending**.

## Retained setup, resources and currentness

Four earlier native frames are retained separately: an optional POSIX-extension
assumption, an incorrect 302 expectation for the normal 303 installer redirect,
an incorrect success-status assumption after a persisted unauthenticated write,
and an error-log expectation while normal mode disables reporting. None invokes
the owner. Stock PHP's id utility and physical proof UID avoid installing POSIX.
Actual state and the temporary diagnostic resolve the status/log assumptions.

Only two capped services run: application **384 MiB / 0.7 CPU / 128 PIDs** and
database **256 MiB / 0.3 CPU / 96 PIDs**, with equal memory/swap limits. Eight
before/after resource captures have no OOM or PID-limit events. Six are fully
zero. Database memory.events max is **46 before and 46 after** the owning suite;
all counters remain unchanged. The original frame similarly has 48 before/after.
The audit retains this pre-existing counter rather than describing all eight
records as zero. No repeat is needed to resolve this observation.

All **30 new / 612 recorded Docker objects** independently verify absent,
including failed phases, one never-started source-extraction container and two
unused helpers automatically created by worker startup. Those exact helper IDs
are removed and verified absent before the next application stack. Both Docker
contexts finish globally empty; owned ephemeral networks and volumes are absent.
All application resources use explicit task/project namespaces. No image/cache
prune or daemon restart is used.

The latest retained set reaches **110 functional cases / 32 profiles**, **47
used/closed OS sessions**, **328 current declared inputs** and **222 zero resource
captures**. No new OS session is counted here. Historical coverage reaches
**327 owners in stated paths, 702 profiles and 4,885 cases**. Registration and
those path counts do not prove full module coverage.

## Self-review

| Area | Assessment |
| --- | --- |
| Summary | Repairs confirmed standalone-check damage and adds a reproducible native-gated profile. |
| What looks good | Exact original-input replay, full option preservation, decoded/whitespace title recovery, real refusal behavior and separately validated RCE primitives. |
| Concerns | Owning RCE/session and exploit cleanup remain pending; inherited payload lint warning and pre-existing static database counter are retained. |
| Suggestions | Exercise actual PHP delivery and its account/file/configuration lifecycle next, then continue the full valuable module inventory. |
