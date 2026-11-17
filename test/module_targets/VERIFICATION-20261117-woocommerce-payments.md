# WooCommerce Payments qualification — 2026-11-17

This checkpoint adds one owner, six qualified profiles and 21 public cases,
reaching **275 runtime owners, 523 qualified profiles and 3,772 historical
functional cases**. The complete serial invocation exits zero; the original
failures remain separately preserved. The broader campaign remains active.

Owner: `auxiliary/scanner/http/wp_woocommerce_payments_add_user`.
The human module guide and its Scenarios remain unchanged.

## Targets and independent setup

Official WooCommerce Payments 5.6.1 and fixed 5.6.2 distributions run on pinned
WordPress 6.8.3, PHP 8.3.28 and MariaDB 11.2.2. The main WooCommerce plugin is
absent. WordPress APIs install/activate the unmodified plugin; all 1,022/1,021
catalogued files match the official archives. The ordinary MariaDB role is
`module_target@%` on `wp_root`; the reporting PostgreSQL role is also nonsuperuser.

The [vendor's historical advisory](https://developer.woocommerce.com/2023/03/23/critical-vulnerability-detected-in-woocommerce-payments-what-you-need-to-know/)
and official source establish the selected affected/fixed releases. Tag commits
are `6464ba6c94d7f1252ad2ec86f34231140d6b53d2` and
`6685af3d60ba3bc3b7d9472551bbe932df5a3da8` in
[Automattic/woocommerce-payments](https://github.com/Automattic/woocommerce-payments).
The vulnerable eager authentication filter is removed in the fixed release.
The release catalog retains archive and complete installed-file checksums.

Independent native prototypes qualify both versions before Framework execution:
18 frozen pre-start inputs each; affected/fixed 13/10 HTTP requests; eight zero
OOM/PID-limit snapshots each. They verify ordinary WordPress pages, anonymous,
administrator, author and nonexistent-user identities, and REST permission
boundaries. The affected probe creates a genuine administrator, checks its
password/capabilities, logs in through wp-login.php, reaches its real admin user
row without the bypass header, then deletes only the probe account via WordPress.
The fixed release rejects the same bypass. Original users, hashes, user metadata,
configuration and vendor files compare equal afterward; complete database
restoration is not claimed because native auto-increment state can advance.
Both two-container prototypes remove their four attached volumes/networks.
Native proofs add no Framework functional cases.

Prototype harness failures are retained separately: two Compose environment
round-trip failures before startup; a recorder API error after the first login
response but before recording it; and an incorrect guessed admin form marker
after successful creation/login. The final marker uses the captured real
`tr#user-ID` row. The latter failed run relies on disposable stack teardown;
it does not claim native account removal. None establishes a module failure.

## Original public results and fixes

Base `20261117T075935-2b54b2` has ten cases and two failures. One is a harness
assertion: public check normally records a vulnerability with the module's
friendly name. The corrected expectation follows the actual reporting capture.
The second is a real owner defect: a valid plus-address email yields HTTP 201
and a native administrator, but interpolated raw-body regexes reject `+` and
omit the credential. Account state, raw response and native removal are retained.
Both native phases pass, with 38 HTTP controls and twelve zero resource snapshots.

The five-profile original batch `20261117T080321-0cfc86` exits 1. Fixed (three
cases), subdirectory, inactive and absent (two each) pass. Plain permalinks has
one failure among two cases despite passing native creation/login controls.
Public POST to `/wp-json/wp/v2/users` returns 404; legacy
`/index.php/wp-json/wp/v2/users` returns a 200 homepage, and the owner stops.
The independent canonical `/?rest_route=/wp/v2/users` returns 201. The owner's
unreached query fallback also contains the incorrect `wp-json` prefix.
All six original profiles clean up, and all thirty attached objects are
individually absent. The failed originals remain preserved and are not counted
as qualified passes.

Repair `6d86d1357d0` parses HTTP 201 through the Framework JSON parser and checks
exact top-level username/email values. It tries the correct query route before
legacy PATH_INFO, retaining termination on every non-404 response so it never
retries a completed or ambiguously acknowledged creation. Same 33 unit examples
produce ten failures against the predecessor and zero with the repair. The
real owner and parser run with disclosed HTTP/UI/DB doubles and captured JSON;
whitespace, mismatch, nested and malformed variants are explicitly synthetic.
Changed-file syntax, RuboCop and module msftidy pass. Parent review verifies all
35 entries in the worker seal and exact bytes of the three imported files.

## Public qualification

Final source: `094505e41cf676c03ef6c77bbc3b5e2dfdadc39c`.
Final run: `20261117T081201-e8b44d`, aggregate CLI exit 0, all 21 examples
passing with no pending cases or outside errors. All 71 declared inputs match
the final bytes; the 69 tracked inputs also match the tested Git revision.

The runner uses fresh Framework configuration/reporting databases and workspaces.
Credential assertions cover exact password, origin module, host/port/protocol,
service, administrator access, successful login status and actual attempt time.
Native password login and admin-page access independently prove each created
account. The test removes owned accounts and verifies original state after each
call. Repeats use the same selected console module and username, with a new native
user ID after cleanup. No loot is expected or created. Version-based check
findings are evaluated separately from runtime permission refusal.

| Profile | Public cases | Native HTTP | Profile test seconds |
| --- | ---: | ---: | ---: |
| Affected/default: repeats, generated values, plus email, no AutoCheck, invalid identities, duplicate and closed port | 10 | 41 | 111.8 |
| Plain permalinks | 2 | 29 | 37.8 |
| Fixed 5.6.2, including ForceExploit refusal | 3 | 20 | 37.1 |
| Subdirectory | 2 | 29 | 37.9 |
| Inactive affected plugin | 2 | 20 | 28.5 |
| Absent plugin | 2 | 20 | 30.0 |

All native before/after gates pass. Seven password credentials and successful
login rows have exact provenance; fourteen scoped findings include passive
version findings for inactive targets. No loot is created. The same console
module object recreates the same username with native IDs 6 then 7. All
original users, roles, hashes, user metadata, configuration and vendor files
compare equal after test-owned cleanup. Seventy-two resource snapshots show
zero OOM/PID-limit events. Actual inspect data confirms all configured resource and loopback
binding limits; every final stack contains three healthy services.

All thirty final attached volumes/networks are individually absent, and the
global container inventory is empty after qualification. Two unrelated MCP
containers observed between the original runs were removed before sealing;
unrelated images and volumes were preserved.

## Reproduction and limits

See [the component guide](woocommerce_payments/README.md) for archive preparation
and the guarded serial launcher. Three services per profile have explicit CPU,
memory/swap and PID caps; only loopback ports are exposed. Containers, attached
volumes and networks are removed after every profile. Unrelated images and
volumes are not pruned. No PR is created; the broader campaign remains active.

The native inactive profile rejects bypass creation while passive public check
still sees affected installed metadata and returns Appears. This finding alone
does not establish a working exploit. Earlier release branches, other core/PHP
versions, TLS, multisite, custom REST restrictions and alternate content layouts
remain unqualified. The required USERNAME option's blank/random internal branch
is not claimed as public functional coverage.

The read-only parent checkpoint is
`/Users/dwelch/.codex/reports/woocommerce-payments-qualified-checkpoint-20261117`,
manifest SHA256 `8964e2220e984a301bcecd0f26b50a6488d4781dd900756d60102f073b42f350`.
Its fourteen entries reference sixteen independently rehashed seals containing
1,548 exact entries: the qualified native proofs, excluded native harness
attempts, all original public profiles, worker before/after and all six final
profiles. Raw console/HTTP responses, reporting rows, source/archive bytes,
resource counters and individual cleanup queries are retained. The qualified
cohort adds only its 21 public cases; native probes and unit examples are
counted separately.

The previous TI publication `272285628dd0` has nine successful workflows and
Meterpreter acceptance queued in the retained 08:10 UTC snapshot. The exact-fork
Ruby 3.4 unit job checks out `272285628dd06e68aac519e7b9d569724795937f`
and passes **20,104 examples, zero failures, 33 pending**. These are the previous
publication's CI results; they do not establish CI completion for this checkpoint.
No CI retry or cancellation was requested.

## Review

- **Summary:** Two confirmed owner defects are repaired and all six profiles pass.
- **What looks good:** Genuine independent vendor/permission controls, exact
  reporting, real password login, repeated creation and cleanup establish the
  complete tested behavior; the human guide is preserved.
- **Concerns:** The deployment limits above and the previous publication's queued
  Meterpreter run remain outstanding. No material issue remains in qualified paths.
- **Suggestions:** Continue with additional valuable owners; keep prior failed
  evidence and passive detection separate from runtime exploitation proof.
