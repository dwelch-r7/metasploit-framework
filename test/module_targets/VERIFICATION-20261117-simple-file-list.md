# Simple File List container verification, 2026-11-17

Qualified one unchanged owner in five profiles with **17 passing public cases in
one aggregate with exit 0**, reaching **280 runtime owners in covered paths,
557 qualified profiles and 3,910 historical functional cases**. The broader
campaign remains active. No PR is created.

Owner: `exploit/multi/http/wp_simple_file_list_rce`, unchanged SHA256
`5c99c087df957cedfe431db8b7d89964d0b852f1ef27a234ea92c45635626fb2`.
The human module guide, including historical Scenarios, remains byte-identical.
No production repair is needed for the covered paths.

## Reproduction and genuine prerequisites

See the [target guide](simple_file_list/README.md). The default five-case profile
checks the actual release and runs each explicit PHP session payload twice.
All five profiles run serially with full teardown between them.

The official [4.2.2 archive](https://downloads.wordpress.org/plugin/simple-file-list.4.2.2.zip)
has SHA256 `639cb105978b36c681fbaec5b3414e96ecb7df97ec6149f6cf3c484a7d3e7b09`;
[4.2.3](https://downloads.wordpress.org/plugin/simple-file-list.4.2.3.zip) has
`04d19f18d807fd54eb29be5ba1dcdf6963a4e53c6b402d10bef4c1bdd308bc70`.
Both complete 112-file catalogs, archive CRCs and safe member paths are checked.
The [CNA record](https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/2020/36xxx/CVE-2020-36847.json)
and actual vendor engine diff identify the 4.2.3 same-extension boundary.

Genuine WordPress 6.8.3/PHP8.3.28/MariaDB11.2.2 use ordinary application grants.
The reporting PostgreSQL role starts with an empty schema and is not a superuser;
Framework creates and uses its real reporting schema. Source catalogs, plugin
header/constant/readme, activation, configuration, UID33 and writable file paths
are checked. Only notification mail is disabled through normal configuration.
No vendor security check, nonce, route response or file operation is fabricated.

Before any Framework call, separate capped two-container native runs prove both
releases. Each records 22 actual HTTP controls, eight zero OOM/PID snapshots,
a callback token/ACK and removal of four attached objects. Public profiles repeat
native gates before and after their module calls. A real shortcode supplies the
uploader timestamp, token and directory. Ordinary ZIP upload, same-extension
rename, exact download and delete work before and after the security boundary.
Wrong tokens and forbidden direct PHP uploads create no file. Harmless PHP bytes
remain inert as PNG; renaming to PHP executes as UID33 only on 4.2.2. On 4.2.3 the
actual endpoint returns HTTP500, logs its extension veto and retains the PNG.

## Selected public aggregate

| Profile | Plugin | Cases | Typed sessions | Native HTTP | RSpec seconds |
| --- | --- | ---: | ---: | ---: | ---: |
| simple_file_list | 4.2.2 | 5 | 4 | 54 | 114.2 |
| simple_file_list_fixed | 4.2.3 | 3 | 0 | 52 | 45.0 |
| simple_file_list_plain | 4.2.2 | 3 | 2 | 52 | 55.0 |
| simple_file_list_subdirectory | 4.2.2 | 3 | 2 | 52 | 57.2 |
| simple_file_list_no_check | 4.2.2 | 3 | 2 | 52 | 54.5 |

Run `20261117T165115-bd1eab` has zero failures, pending cases or outside errors, with all
teardown checks passing. Ten real sessions comprise five PHP Meterpreter sessions
with embedded stdapi and five PHP command shells. Every actual session performs
a native-verified UID33 file operation. Repeated calls retain the selected console
module while actual execution objects differ. The explicit AutoCheck-disabled
runs execute successfully without an automatic-check invocation.

The fixed target's normal run stops before upload. With AutoCheck disabled, its
real PNG upload succeeds and renaming is rejected with HTTP500; no PHP file or
session exists. The retained owned PNG is recorded and removed through the real
vendor Delete endpoint. This is operator recovery, not automatic module cleanup.

Actual PostgreSQL observations contain 12 distinct scoped vulnerability
findings, including 10 in contexts without a session;
they are not that many exploitation proofs. Credentials and loot remain empty,
as expected for this owner. Physical FileDropper removal is verified independently
before a normal shortcode view refreshes the vendor file-list index. Selected
users/password hashes/roles/session tokens/usermeta, configuration/options,
page, complete upload tree and immutable source state are restored.

## Preserved setup and harness results

The first native attempt stops after successful ordinary file operations because
its integrity expectation incorrectly included two vendor-owned mutable logs.
Exactly `logs/ee-file-error.log` and `logs/ee-upload-error.log` change with genuine
PHP FILTER_SANITIZE_STRING deprecation messages. All other 110 archive files and
selected state match. The failed attempt is sealed before the narrow correction:
full 112-file installation/first-boot verification remains; subsequent checks
compare 110 immutable files and preserve the two logs separately. Vendor source
and the owner are never patched to make the lab work.

A private controller-generator edit also fails its occurrence-count guard before
writing. The initial native attempt therefore retains its original frozen
controller. The corrected controller adds a normal post-boundary file operation.
No module failure or coverage is attributed to these preparation errors.

An earlier public five-case baseline also passes with four real sessions. It is
archived separately and adds no counts beyond the selected 17-case aggregate.
There are no public baseline failures to hide or owner fixes to infer.

## Resources and limits

The selected aggregate makes 262 independent native HTTP requests, records
8 benign native execution proofs, 10 exact callback successes
and 60 zero OOM/PID snapshots. One stack runs at a time,
with at most three capped work containers. CPU/memory/swap/PID/init settings and
loopback port bindings are inspected. All 25 attached volumes/networks must be
individually absent after teardown. No unrelated image or volume pruning occurs.

Vendor error logs, dynamic `eeSFL-Log`, unrelated WordPress options, auto-increment
and free-space differences are outside selected state restoration; full database
restoration is not claimed. The native HTTP file controls use unauthenticated
endpoints, just as the actual owner does.

Default/staged/dynamic PHP transport remains unqualified under the separate
[transport investigation](DEFERRED.md#wordpress-staged-php-meterpreter-repeat-execution).
Other plugin/runtime releases, TLS, multisite, custom upload directories and
other security configurations are unqualified. This contemporary pinned runtime
does not establish the historical Debian/WordPress/PHP scenario.

Ruby syntax and RuboCop pass for the three new Ruby files. All five Compose plans
and declared input manifests pass preflight. No full RSpec suite is run. Private
source/native/public archives retain immutable inputs, raw results, transcripts,
resource observations and exact cleanup queries with SHA256 manifests. Publication
CI is reported separately and is not evidence of executing these opt-in labs.
