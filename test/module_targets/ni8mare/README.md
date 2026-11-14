# n8n authenticated file and owner-ticket extraction

These profiles exercise `auxiliary/gather/ni8mare_cve_2026_21858` against genuine
official Linux amd64 n8n images pinned by digest: affected 1.120.0 and protected
1.121.0. See the [dated verification report](../VERIFICATION-20261114-ni8mare.md)
for the accepted cases, exact results and remaining limits.

```sh
DOCKER_CONTEXT=default BUILDX_BUILDER=default bundle exec ruby tools/dev/run_guarded_module_target_tests.rb ni8mare ni8mare_fixed
```

The affected profile covers binary, text, empty, Unicode and 65,537-byte files,
a filename containing spaces and Unicode, owner-ticket extraction with ordinary,
plus and slash hash claims, incorrect credentials, an absent target user,
missing and inaccessible files, and a refused connection. The protected profile
checks real public request rejection, no disclosure/token, bad credentials,
missing files, file-to-session action transitions and a refused connection.
Each case repeats its public operation. Reuse means the selected console module;
Framework may execute a fresh replica for each `run`.

The module logs in as a genuine `global:member` whose password differs from the
owner's. Fixture data creates a disposable member and personal project using the
installed user/project schema; the real login and workflow APIs establish its
permissions. The test verifies that this password cannot authenticate the owner.
Token acceptance uses an independent client and only the module-produced ticket;
it requires the intended owner ID, email, role and `user:create` permission.
This proves an application authentication ticket, not an OS payload session.

Native controls use genuine owner setup, manual Form Trigger workflows,
multipart uploads, JSON content-type confusion and actual execution data.
Installed `flatted` decodes serialized execution without numeric array-position
assumptions. Native database/config reads verify actual user rows and the
generated encryption key. The protected release must accept genuine multipart
uploads while rejecting JSON confusion with its installed content-type guard.
No application endpoint or vulnerability implementation is replaced.

Ordinary, plus and slash token-hash fixtures use a fixed valid bcrypt hash.
Native setup changes only disposable account data, verifies normal password
login and restores the original account. Standard Base64 is required for the
user-hash claim; the JWT envelope remains base64url. Independent native controls
reject altered claims and bad signatures. Persisted Framework credentials must
be nonreplayable bcrypt hashes with the actual database-loot import origin.

Fixture management reuses cookies genuinely issued during normal native login.
Public module calls retain the default five-per-minute login policy and wait
within that budget. No limiter is disabled. Native preparation can honor one
bounded server Retry-After response. Readiness requires genuine settings JSON;
`/healthz` alone can return 200 during startup.

Complete unrelated workflow records and the global SQLite workflow-ID registry
must match around module calls, including failures. The test creates two foreign
workflows before execution, checks them unchanged, removes only its fixtures,
and repeats native calibration after module execution. Logical execution tables
must return to zero. The guarded runner removes its entire ephemeral Compose
project even when acceptance fails.

At most three capped containers run: target 1,536 MiB/one CPU, Framework
1,024 MiB/one CPU and reporting database 256 MiB/0.2 CPU. Swap equals memory;
published ports bind to localhost. Worktrees share the serial runner lock.
A root-owned mode-000 fixture and a real UID-1000 EACCES probe establish the
inaccessible-file negative; root access is confined to fixture creation/removal.

Database probes can grow SQLite free pages because execution data contains a
copy of the live database. Fixture compaction runs only after complete workflow
records match and execution tables are empty. It hashes every application table
and schema before/after VACUUM to require unchanged logical data. The public
module's database and config extraction use the actual target files.

Coverage is limited to these two versions, the default single-process SQLite
configuration, default derived JWT signing secret, MFA-disabled owner, root URL,
and representative small databases. External databases, custom JWT secrets,
MFA, alternative binary storage, queue mode, reverse proxies, other versions and
large-database stress remain unqualified. The module exposes no TARGETURI option.
