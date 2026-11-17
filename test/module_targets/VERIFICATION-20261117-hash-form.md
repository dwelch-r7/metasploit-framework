# Hash Form upload and check verification, 2026-11-17

Qualified one owner in nine profiles with **37 passing public cases in one
aggregate with exit 0**, reaching **281 runtime owners in covered paths,
566 qualified profiles and 3,947 historical functional cases**. The broader
campaign remains active. No PR is created.

Owner: `exploit/multi/http/wp_hash_form_rce`. The narrow check/description repair
is `a9bf9dd74fb038114109270f6ede31bcf62a0d8f`, imported from the separate
`fix-hash-form-version-detection` worktree commit
`fe7afbb9744952425a676be0a86e1a57e2c637f7`. The exact tested owner SHA256 is
`eac3a97919407a5acf9ea3f7db40ac5f71c3b23df737e1a441950aba798c0359`.
Contracts are isolated in `fff565085f3`, imported from
`bbec4efdf81c0bc3200fda7c633791e712a05301`.

## Reproduction and source scope

See the [target guide](hash_form/README.md) for preparation, profiles and limits.
The default nine-case profile checks the real release, repeats each of three
payload families, and exercises actual missing-base/nonce failures. Other
profiles select backend, version, routing and AutoCheck paths.

Official complete archives have pinned SHA256 digests and full installed-file
catalogs in [releases.json](hash_form/releases.json). Selected releases are
1.1.0, 1.1.4, 1.1.5, 1.1.6 and 1.1.9. Genuine WordPress 6.8.3, PHP 8.3.28 and MariaDB 11.2.2
use ordinary application grants; the PostgreSQL reporting role starts with an
empty schema and is not a superuser. Framework creates and uses its actual
reporting schema. Source, header/constant, form/field/entry tables, users,
configuration and filesystem identity are verified.

The [CVE-2024-5084 CNA](https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/2024/5xxx/CVE-2024-5084.json)
identifies the original <=1.1.0 upload flaw. The additional 1.1.4/.5 behavior here
comes from actual official-source and runtime evidence; this report does not
claim that the CNA record was extended. The separate
[CVE-2024-9417 CNA](https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/2024/9xxx/CVE-2024-9417.json)
describes limited uploads outside allowed/forbidden lists. Its non-PHP TXT path
is observed on 1.1.6/.9 and is kept separate from PHP execution.

## Confirmed check defect and source-only repair

The unchanged 1.1.0 root cohort passes all seven initial cases, including two
PHP Meterpreter sessions, two Bash sessions and two fetched Linux Meterpreter
sessions. Genuine 1.1.4 instead returns Safe/not exploitable through public
check, while all three forced session families execute native-verified UID 33
operations. Its four-case forced cohort fails only the check assertion.

The normal 1.1.4 cohort is **4 examples/4 failures**: the false Safe result blocks
all three runs. Native gates before/after, callbacks, resources and teardown
pass. Changing only the owner among **112 declared inputs** makes the same
four cases pass with three usable sessions; all other 111 inputs remain byte
identical. Unit contracts are not imported during that causal replay.

The repair retains the original <=1.1.0 interval and returns passive Appears for
1.1.4 <= version <1.1.6. Actual PHP execution still depends on the web server.
Options, targets, payload selection and artifact retention stay compatible.
Twenty focused contracts execute the real readme parser and version comparison
with doubled WordPress availability, HTTP transport and service persistence.
The original aggregate is **27 examples/2 failures** (only 1.1.4/.5), then **27/0**;
seven automatically loaded support cases are separate from the 20 contracts.
Both raw CLI outcomes and complete logs are preserved.

## Target and backend evidence

Native controls create a real form/upload field through vendor APIs. Actual
preview HTML supplies its nonce and extensions. Ordinary uploads and native
Delete work before and after security probes; wrong/missing nonces, wrong-delete
nonce, extension and size behavior are independently tested. Callback controls
exchange exact tokens/ACKs; a native curl request verifies the host fetch route.
No vendor file, security response or form nonce is fabricated or patched.

Preserved prerequisite results explain why version labels alone are insufficient:

- 1.1.1 ordinary GIF upload fails with a vendor `explode(array)` TypeError. It is
  excluded as a working positive control. 1.1.2/.3 argument inconsistencies are
  source observations, with no passing runtime claim.
- 1.1.4 contradicts the initial advertised-fixed denial expectation: benign PHP
  actually executes. The failed expectation is sealed before an explicit
  execution/recovery probe passes. Its missing vendor stub paths remain intact.
- 1.1.5 on Apache uploads PHP but serves exact literal source through its genuine
  `.htaccess` handler. The original failed execution expectation is retained.
  On the same pinned image's real PHP development server, uploaded PHP executes
  as UID 33 with SAPI `cli-server`, while all vendor handler files remain intact.
  This qualifies that backend, not Nginx, IIS or Windows.
- 1.1.6/.9 remove multipart fallback and allow non-dangerous TXT outside the GIF
  request list. Those release-specific observations are recorded. Exact PHP
  requests create no file, including a vendor argument error on that input;
  ordinary XHR continues to work. They are not whole-plugin security proofs.

## Selected aggregate

| Profile | Plugin | Backend / PHP result | Cases | Typed sessions | Native HTTP | RSpec seconds |
| --- | --- | --- | ---: | ---: | ---: | ---: |
| hash_form | 1.1.0 | apache / execute | 9 | 6 | 76 | 118.7 |
| hash_form_reintroduced | 1.1.4 | apache / execute | 4 | 3 | 68 | 72.0 |
| hash_form_reintroduced_last | 1.1.5 | phpdev / execute | 4 | 3 | 68 | 96.3 |
| hash_form_apache_upload_guard | 1.1.5 | apache / source | 2 | 0 | 65 | 43.6 |
| hash_form_php_boundary | 1.1.6 | apache / deny | 3 | 0 | 54 | 34.3 |
| hash_form_fixed | 1.1.9 | apache / deny | 3 | 0 | 54 | 33.0 |
| hash_form_plain | 1.1.0 | apache / execute | 4 | 3 | 68 | 71.9 |
| hash_form_subdirectory | 1.1.0 | apache / execute | 4 | 3 | 68 | 76.6 |
| hash_form_no_check | 1.1.0 | apache / execute | 4 | 3 | 68 | 76.8 |

Run `20261117T175413-29077e` has no failures, pending cases or outside errors, with all
teardowns passing. **21 actual sessions** comprise seven PHP Meterpreter sessions
with embedded stdapi, seven Unix Bash shells and seven HTTP-fetched Linux x64
Meterpreter sessions. Each performs a native-verified UID 33 file operation.
Repeated calls retain the selected console module; actual execution objects
differ. AutoCheck-disabled runs execute without an automatic-check invocation.
Both real missing-base/nonce cases leave no sessions or payload files.

Twenty-one actual owning payload sources are captured with UID/size/SHA256.
Seven PHP files equal the actual cached encoded payload bytes. Command wrappers
and their actual cached commands are captured without regeneration. Graceful
remote shutdown is requested, and all seven fetched binaries and native process
IDs are independently absent. No session or job remains at profile completion.

The owner retains uploaded PHP. Tests record **22 owned files**
(21 session uploads plus one Apache-guard upload) and remove only those files
through the native encrypted-path Delete API after path/UID/hash checks. This is
operator recovery, not automatic module cleanup. Selected source, user identity/password/role/token fields and usermeta,
form/field/entry tables, plugin options, page identity/content/URL, config and
complete upload-tree state match before/after. First-upload directory
initialization is recorded separately. Unrelated options, logs, counters and
whole-database restoration are outside that claim.

Actual PostgreSQL observations contain 26 distinct scoped findings,
including 8 in workspaces without an
observed owning session. They are database observations, not that many execution
proofs. Credentials and loot remain empty. Finding contexts are classified by
joining observed session labels to owning-call workspaces, not by searching the
finding description for a session marker. This audit also corrects the earlier
[Simple File List report](VERIFICATION-20261117-simple-file-list.md) from ten to
four no-session contexts; its 17 passing cases and ten actual sessions are
unchanged, and all original immutable archives are retained.

## Resources, validation and limits

The selected aggregate records **589 native HTTP controls**,
12 benign native execution proofs,
2 native literal-source guards, one owning literal-source
case, 18 exact TCP callbacks, 18 native HTTP fetch
controls and 108 zero OOM/PID snapshots. One public stack
runs at a time with at most three capped containers, totaling 1.75 CPUs/1,408 MiB.
Linux/amd64, memory/swap, CPU, PID/init and loopback bindings are explicit and
verified. The PHP server has four bounded UID 33 workers. All **45 attached
volumes/networks** are individually absent after teardown. No unrelated image
or volume pruning occurs.

Changed Ruby syntax/RuboCop, owner msftidy, human-guide msftidy_docs, PHP syntax,
and all ten registered Compose/input plans pass. The forced 1.1.4 diagnostic is
outside the selected nine-profile aggregate and adds no counts again. No full
RSpec suite is run. The human guide's historical Scenarios remain byte-identical.
Private immutable source/native/public archives retain raw outcomes, actual
inputs, transcripts, observations and exact cleanup queries with SHA256 manifests.

Windows, default/staged/dynamic PHP, other runtime releases, TLS, multisite,
Nginx/IIS, and other upload/server settings remain unqualified. Publication CI
is reported separately and is not evidence of executing these opt-in labs.
