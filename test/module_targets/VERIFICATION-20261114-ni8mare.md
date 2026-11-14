# n8n authenticated file and owner-ticket extraction

The covered paths of `auxiliary/gather/ni8mare_cve_2026_21858` pass against genuine
n8n 1.120.0 and protected 1.121.0. This advances the campaign to **244 modules
qualified in covered paths, 300 profiles and 2,862 unique functional examples**.
The broader campaign remains incomplete. No PR is created.

```sh
DOCKER_CONTEXT=default BUILDX_BUILDER=default bundle exec ruby tools/dev/run_guarded_module_target_tests.rb ni8mare ni8mare_fixed
```

| Profile | Genuine target | Cases | Public calls | Result |
| --- | --- | ---: | ---: | --- |
| `ni8mare` | Official Linux amd64 n8n 1.120.0 | 14 | 28 | Pass |
| `ni8mare_fixed` | Official Linux amd64 n8n 1.121.0 | 6 | 14 | Pass |

Run `20261114T151306-009e51` completes with controller, manager and observer exits
zero. Both RSpec reports have zero failures, pending cases and outside-example
errors. Their durations are 390.71 and 173.59 seconds; the complete serial
invocation takes 632.18 seconds, including native preparation and teardown.

## Target fidelity and covered behavior

The Compose profiles pin official image digests:

- 1.120.0: `n8nio/n8n@sha256:e5733e0dee8de5f7a96d950fdca2a8729bb56b8b5304d62e3a06feb703985136`.
- 1.121.0: `n8nio/n8n@sha256:435353df610295746ea922d4b933bfbf63449543df9d62dcc552dd664ea09dc9`.

Both use Node v22.21.0 and SQLite 3.50.4. Installed application/dependency source
fingerprints are checked before and after execution. Native controls use real
owner setup, member login, Form Trigger workflows, multipart uploads, JSON
content-type confusion and serialized execution data. Installed `flatted.parse`
decodes the actual responses. Database/configuration controls verify real user
rows and the generated encryption key. No application endpoint or vulnerability
implementation is replaced.

Public module calls authenticate as a genuine `global:member` with a password
distinct from the owner's. Fixture data supplies its personal project and
membership using the installed schema; real login/workflow APIs verify its
permissions. Native controls establish that this password cannot authenticate
the owner. Module-produced tickets are presented through an independent client
with no helper-admin-cookie fallback. Their actual user ID, email, owner role
and `user:create` scope must match the selected account. The audit separately
parses each ticket and verifies its HMAC using the genuinely extracted key.
This establishes an application authentication ticket, not an OS payload session.

The affected profile repeats six exact file cases: binary, text, empty, Unicode
content, 65,537 bytes, and a filename containing spaces and Unicode. All twelve
saved loots match the expected bytes. Ordinary, plus and slash hash claims each
produce two accepted owner tickets. Persisted bcrypt credentials must have
nonreplayable-hash type, detected `bf` format, the correct workspace/user and an
import origin referencing genuine SQLite loot.

Incorrect credentials and refused connections produce no loot or credentials.
An absent selected user retains only genuine database loot. Native-proven
missing and root-owned mode-000 files fail without disclosure and restore the
workflow registry. UID 1000 receives real EACCES on the inaccessible fixture.
The protected profile makes ten calls that must fail through the real public
HTTP 500 content-type guard, plus four credential/connection negatives. It
also repeats file-to-session action transitions. Genuine multipart uploads
still succeed on that release, distinguishing the fix from a broken server.

## Source defects and focused regressions

The original JWT user-hash claim used Base64url. Ordinary tickets worked, while
correctly signed plus/slash tickets received HTTP 401. The claim now uses
standard Base64, and the JWT envelope retains Base64url. Extracted bcrypt hashes
are reported as hashes with database-file origins rather than replayable
passwords or validated logins. SQLite handles close on success and error.

A rejected public upload previously bypassed success-only workflow deletion.
The native protected target retained the exact newly created member workflow
while foreign workflows stayed unchanged. Cleanup now captures owned IDs,
origin and cookies, runs on success/failure, retries uncertain removal and
chains parent cleanup while preserving primary failures and useful loot. Later
runs reset ownership state; unconfirmed removal reports exact manual-cleanup IDs.

The broader console replay caught an intermediate parameter-binding regression:
ASCII-8BIT email strings bind as SQLite BLOB values and miss existing TEXT rows.
Independent queries of all three genuine downloaded databases demonstrate the
difference. Local validated UTF-8 duplicates fix the lookup without mutating
datastore strings or interpolating SQL.

Unicode filenames exposed HTTP framing: real Rex serialization declared 179
bytes for a 182-byte body. JSON itself preserved the path, and native Unicode
reads worked. Upload JSON is now sent as bytes after validating text inputs.
Invalid UTF-8 receives BadConfig and still cleans its created workflow.
The shared HTTP library is unchanged.

Byte-exact replay then caught fixed-index parsing: real 32-entry Flatted tables
store data at element 29, while a 33-entry response stores `txt` there.
Permissive decoding silently saved two wrong bytes. The fix follows the owned
form's actual binary references with bounded traversal, preserves empty and
numeric-looking string literals, strictly decodes Base64 and rejects malformed,
cyclic or ambiguous input. The two small native captures and installed-parser
oracle hashes are committed under `spec/file_fixtures/modules/auxiliary/ni8mare_execution_data`.

| Focused before/after source suite | Examples | Failed before | Failed after |
| --- | ---: | ---: | ---: |
| JWT/hash/SQLite contracts | 12 | 8 | 0 |
| Owned-workflow cleanup | 26 | 20 | 0 |
| Console text boundaries | 11 | 9 | 0 |
| Flatted file extraction | 21 | 19 | 0 |

These compare the predecessor of each fix with its corresponding implementation;
failed expectations are not separate defect counts. Final-source parser 21,
JWT/hash 18, text 5 and cleanup 26 cases all pass: 70 distinct focused cases.
HTTP transport/reporting/storage boundaries are disclosed doubles; SQLite,
claims/signatures, cookie jars, JSON and Rex serialization are real. Genuine
functional acceptance supplies the application evidence. Selected-console reuse
may execute a new Framework replica; direct same-object tests separately cover
ownership reset contracts.

The legitimate binary mismatch also broke RSpec JSON failure rendering. Its
original empty JSON and raw `14 examples, 1 failure` text are preserved without
reconstructed JSON counts. Exact-byte assertions now compare canonical Base64
strings. A deliberate incorrect binary value produces actual exit 1, one ordinary
failure, zero outside errors and valid JSON. Initial helper, encoding-namespace,
style and setup failures are retained separately from source verdicts.
Strict changed-file RuboCop, module/docs tidy, syntax and diff checks pass.
Historical human module-guide Scenarios remain byte-identical.

## Resources, restoration and evidence

At most three capped containers run: target 1,536 MiB/one CPU, Framework
1,024 MiB/one CPU and reporting database 256 MiB/0.2 CPU. Swap equals memory;
ports bind to localhost. The shared lock serializes worktrees. The first console
starts cold; the second profile uses only the same invocation's ordinary
metadata seed. Live prompts, cache provenance and caps are independently checked.

The genuine default five-per-minute login policy stays enabled. Public calls
wait within that budget; native fixture management reuses normally issued
cookies. Complete foreign workflow records and global SQLite workflow IDs match
around calls. Fixtures are removed back to the original registry. Only after
workflow restoration and zero execution rows does fixture VACUUM run; all 103
checks preserve every application table and schema. All 107 native probe
invocations exit zero. Cgroup OOM and PID-limit counters stay zero.

All sixteen exact-resource/project/global teardown queries pass. Five final
inventories are empty, and the shared lock is free. No unrelated containers
remain. No images or unrelated volumes are pruned. Earlier setup OOM observations
from SQLite free-page growth are preserved; they are not attributed to the
source handle-closure defect.

Read-only local archives retain raw output, selected inputs, process exits and
independently rehashed manifests under `~/.codex/reports/`:

| Archive suffix, each ending `-20261114` | Manifest SHA-256 |
| --- | --- |
| `ni8mare-native-calibration` | `0bc7447ffc3fc4a5f62784d57c4e69d76bbff0adcfd00032da24d707e494ae89` |
| `ni8mare-member-native-calibration` | `986ac8ea03ce60111c64df39f295b92d20684816ba8cb260c4efdf8ba0bc0482` |
| `ni8mare-original-token-failure` | `3c8e3fbc8303f9de6039a990a02bc8a02c61869a5a62d28bf76a164279e09458` |
| `ni8mare-guard-cleanup-failure` | `d5eb19677c90d4ada8648782a3f6aa38fcda3ea441bb3dc810589313d4bd9626` |
| `ni8mare-console-text-failure` | `bbe0de63ba7b5d67cd191be43da415e5cd7882b42bb0b79cfcbc20e0842dbd98` |
| `ni8mare-console-text-diagnosis` | `0fc2558eb12e6c7cd07f2d75464ec54c3d8b66a308dd24f13902faf2bc6729dc` |
| `ni8mare-flat-parser-failure` | `2ff7203850ef8d394fd05d0f3878d757f67b650ef663a6ed08e90fb548649b99` |
| `ni8mare-qualified` | `2061cc23cc6e047d0f3926dd2981c68b761871da41f59c372ff14e7d8a2cf891` |

The final archive has 2,239 files and 49 selected inputs, no hardlinks, and all
files/directories read-only. Executable/configuration inputs match publication;
the recipe README's post-run documentation-only change replaces its pending
sentence with this report link. Its accepted/publication hashes are recorded in
the publication receipt. Module source SHA-256:
`5d28b6817c3ac07d4bbe395fbe669a7b8fd9ca9d006d97eded857c73bc49e8d3`.
Preserved Scenarios SHA-256:
`7a7e50b85144e41aa2faaac1bf46e62bca1d6f9b90545cb8c731ff5608af233f`.

Coverage is limited to these releases, root URL, default single-process SQLite
and binary storage, the default derived JWT secret and an MFA-disabled selected
user. External databases, custom secrets, MFA, other releases, queue mode,
reverse proxies, alternative storage and large-database stress remain unqualified.
Static inventory contains 5,179 sources, 246 registered owners, 22 individual
reviews, zero stale reviews and 255 pending documented-container reviews.
Registration is not qualification. Standing path deferrals remain `druid_js`,
`freeswitch_batch`, `superset_rce_owner` and `wordpress_admin`.
