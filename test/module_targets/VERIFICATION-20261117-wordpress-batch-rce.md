# WordPress batch desync RCE qualification, 2026-11-17

One new runtime owner, eleven qualified profiles and 36 functional cases bring
the campaign to **273 runtime owners in covered paths, 508 qualified profiles
and 3,738 historical functional cases**. The independent authenticated-upload
payload control adds no extra campaign counts. Earlier coverage remains
historical; the broader campaign is active. No PR is created.

The owner is `exploit/multi/http/wp_batch_desync_rce`. Its source is unchanged,
SHA256 `5a6d31bca44b6a16a04f2cf46d1a530e616b0251b62aa9e593144970a39bfd14`.
Fixture commit: `478031e82ad8581a8084ac87ffbdc075257cbfd0`.
The [human module guide](../../documentation/modules/exploit/multi/http/wp_batch_desync_rce.md)
and its Scenarios are preserved, SHA256
`e478925bd9ac1137f4ed4ef3a19caae998a4e99504895bfa6b26005b4d517bb0`.

## Qualified public behavior

| Profile | Core | State | Cases |
| --- | --- | --- | ---: |
| `wp_batch_desync_rce` | 6.9.4 | Defaults, both session families twice, explicit discovery without AutoCheck, collision, invalid prefix and unreachable check/run | 10 |
| `wp_batch_desync_rce_fixed69` | 6.9.5 | Fixed release refusal | 2 |
| `wp_batch_desync_rce_70` | 7.0.1 | Check and both session families | 3 |
| `wp_batch_desync_rce_fixed70` | 7.0.2 | Fixed release refusal | 2 |
| `wp_batch_desync_rce_subdirectory` | 6.9.4 | `/wordpress/`, both session families | 3 |
| `wp_batch_desync_rce_prefix` | 6.9.4 | `wp_native_` tables, both session families | 3 |
| `wp_batch_desync_rce_plain` | 6.9.4 | Genuine plain permalinks, both session families | 3 |
| `wp_batch_desync_rce_no_posts` | 6.9.4 | No published post or page; detects SQLi and refuses execution | 2 |
| `wp_batch_desync_rce_page_only` | 6.9.4 | Native published page with no blog post, both session families | 3 |
| `wp_batch_desync_rce_upload_disabled` | 6.9.4 | `DISALLOW_FILE_MODS`, two denied uploads with account cleanup | 3 |
| `wp_batch_desync_rce_keep_admin` | 6.9.4 | Preserved account verified before explicit operator removal | 2 |

These are twelve public checks and 24 public runs. Sixteen runs prove actual
session type and native command execution: nine Linux PHP Meterpreter sessions
and seven Unix command-shell sessions. Each session creates a proof file whose
owner is independently verified as UID 33, then removes that test file and
closes sessions/jobs. Root PHP and shell repeats reuse the same actual module
object, with native account/plugin restoration between executions.

The first PHP run uses the actual default target and payload without setting
`TARGET` or `PAYLOAD`. Other PHP runs explicitly use
`php/meterpreter_reverse_tcp`; shell runs use `cmd/unix/reverse_bash`.
The explicit-discovery case sets `AutoCheck=false`, `TablePrefix` and
`WpAdminId` and still initializes the execution chain correctly.

## Independent target prerequisites and reporting

The labs reuse the four pinned official archives and complete vendor-file
catalog from [WP2Shell](wp2shell/README.md), with PHP 8.3.28 and MariaDB 11.2.2.
Every profile verifies all installed vendor digests, archive identity, database
role/grants, four real users, posts/pages, paths, permalinks, cache absence and
configuration. No vendor PHP is patched and no endpoint response is simulated.
Independent HTTP and complete in-band native extraction controls run before and
after public calls: 110 native HTTP requests across the qualified profiles.
A separate exact-token PHP callback validates the current app-to-host route
before payload execution.

Before the Framework fixtures, the unmodified referenced
[wp2shell PoC](https://github.com/Crypto-Cat/wp2shell/tree/e7220d170f9e8cb2217d6d9b6485a03345e2d54e)
was retrieved at that commit and verified as SHA256
`54fa9d7d57f3734166719697b2340d53da7d3b617fa2ac4be232004453bc63a9`.
It independently executes `/usr/bin/id -u` as UID 33 on 6.9.4 and 7.0.1 and
refuses 6.9.5 and 7.0.2. Those four native trials add no Framework coverage.
Private evidence records the exact source identity and executed call-graph
review; the external PoC is not vendored into Framework.

Fresh ordinary-role PostgreSQL reporting databases and console configurations
are used per profile. Fifteen credential cores have the exact created password,
service origin, WordPress endpoint, successful administrator login and attempt
timestamp. Repeated accounts retain their credential/service/login IDs.
Eighteen loot files match their expected bytes, digests and database metadata.
Upload refusal occurs after administrator authentication, so that profile
correctly retains one credential/login and two loot records.

Application findings use the WordPress service and expected CVEs. Framework's
separate automatic session-exploitation finding uses the HTTP transport service;
the audit verifies its endpoint, references and session-exploitation reason.
This extra transport finding is legitimate, not an owner reporting defect.

Uploaded plugins and created accounts are removed, except when `KeepAdmin`
deliberately preserves the account. That account's administrator role and password
are checked natively before explicit operator cleanup. Original users/usermeta,
plugin trees, configuration, vendor source and original posts are preserved.
New cache/changeset/request posts and postmeta changes are recorded. Full database
restoration is not claimed. Successful chains also emit secondary SQL syntax
errors through the nested changeset/REST re-entry stack; exact logs are retained
and classified rather than described as error-free.

## Failed attempts and profile-only repair

The first root attempt assumes a default page that the shared seed intentionally
removes; its native prerequisite stops all ten examples before any module call.
The second sets `TARGET=0`, which the console demonstrably switches to staged
`php/meterpreter/reverse_tcp`. Staged callbacks receive a stage but fail session
negotiation/extension loading. One recorded SIGINT ends the stalled console.
That attempt is not a clean completion or qualified staged-session proof.

A later root attempt opens both intended session families but exposes two test
assertion defects: scalar RSpec state does not persist between examples, and
the reporting assertion rejects the legitimate automatic HTTP finding. The
corrected root profile passes all ten cases. Failed attempts remain sealed.

Full matrix `20261117T035823-c0b30e` finishes with actual CLI exit **1**: ten
profiles pass 33 cases, while the upload-disabled profile fails three examples
in its before-all native configuration gate, with **zero public module calls**.
Docker exec PHP does not inherit the environment append made by PID 1. The
generated official wp-config reads environment at every bootstrap, so that
native process observes `DISALLOW_FILE_MODS=false`. The original HTTP flag was
not directly measured by this failed trial.

Only that profile's launcher, Compose, manifest and README change. The launcher
writes inherited configuration plus the component flag to the official image's
`WORDPRESS_CONFIG_EXTRA_FILE`, which both HTTP and Docker exec PHP read. Shared
core defaults remain in their existing component. Replay
`20261117T041708-021783` confirms the native flag and passes all three cases,
actual CLI exit **0**. The other ten passing profiles retain exact current inputs.
No all-green 36-case aggregate is claimed.

Independent authenticated uploader control `20261117T041519-c2f44b` passes one
case with the intended inline PHP payload, typed session, UID-33 proof and plugin
removal. It verifies Ruby 3.3.13, payloads 2.0.257 and the actual installed PHP
Meterpreter source. Authentication metadata and new posts are recorded, not
claimed to be restored wholesale. This calibration does not establish the cause
of the staged failure. Existing administrator-uploader staged profiles also
remain unqualified; the separate protocol diagnostic below records a reproducible
transport defect while leaving historical causation unresolved.

## Separate staged-transport diagnostic

Exact installed PHP Meterpreter source from payloads 2.0.257, SHA256
`e031bea39090ccc1c3086474c971c00368006e9105aa198d783f94225b36740d`,
is exercised against an independent unencrypted Meterpreter protocol peer.
Native PHP/UID, callback, configuration parser, resource and OOM/PID controls
pass. Three whole requests work, including a 59,276-byte `core_loadlib` request
that registers and dispatches a benign extension command. The same small/large
request bytes split within a header or body fail: the peer closes before the
remainder is sent after at least 250 ms. All six PHP children exit zero naturally.

The first controller also has a false assertion: it checks the UINT meta-type
131072 instead of `TLV_TYPE_UINT` 131083, defined in
[packet.rb](../../lib/rex/post/meterpreter/packet.rb). Its original failure is
sealed before correcting that assertion. The corrected replay retains three
whole-request passes and three fragmented-request failures. Both controller
invocations have actual exit **1**; neither is relabeled successful. Request bytes
are unchanged between attempts; recorded callback ports necessarily differ.
The parent independently decodes seven complete wire replies, including the
registered command and its successful execution, and verifies actual caps.

`dispatch_tcp` reads a header without accumulating all 32 bytes, and treats a
temporary empty body read as a closed connection. This controlled defect is
confirmed for the exact installed source. Local payloads revision is
`74c28abb12135ad7dbdcdca2e934f414701f3c30`; remote source freshness is unverified.
The historical RCE failure still lacks labeled wire frames establishing its
initiating event. A C2-specific buffering repair and genuine staged-session
replay remain further work. No production source is changed and no Framework
module/session cases are added by this protocol diagnostic.

Each attempt uses one cached PHP container at 0.5 CPU, 256 MiB/equal swap,
64 PIDs, init and UID 33, with a read-only root filesystem and no published ports.
Both containers are removed; no anonymous volumes are created. Global inventory
is empty and the exclusive lock is reacquired/released afterward. The separate
196-entry comparison seal is
`/Users/dwelch/.codex/reports/php-staged-framing-comparison-20261117`, manifest
SHA256 `303430f6a53f965f47eb642c786a51b5c6f32948e9504b478ff5133d76dec300`.
Its complete file set and all bytes, including the nested 99-entry original seal,
are independently rehashed.

## Reproduction, source identity and limits

```sh
DOCKER_CONTEXT=default BUILDX_BUILDER=default \
  bundle exec ruby test/module_targets/wp2shell/prepare.rb
DOCKER_CONTEXT=default BUILDX_BUILDER=default \
  bundle exec ruby tools/dev/run_guarded_module_target_tests.rb \
  wp_batch_desync_rce wp_batch_desync_rce_fixed69 wp_batch_desync_rce_70 \
  wp_batch_desync_rce_fixed70 wp_batch_desync_rce_subdirectory \
  wp_batch_desync_rce_prefix wp_batch_desync_rce_plain \
  wp_batch_desync_rce_no_posts wp_batch_desync_rce_page_only \
  wp_batch_desync_rce_upload_disabled wp_batch_desync_rce_keep_admin
```

All 127 unique declared inputs, including the independent control, match 123
exact committed blobs at the fixture commit plus four ignored official archives.
Runs captured dirty working-tree bytes at their recorded earlier revision;
the audit maps those actual bytes to the commit, rather than claiming the run
checkout was clean at that commit. Four changed Ruby files have zero RuboCop
offenses, the owned shell launcher parses, all Compose plans and actual resource
caps pass, and the static queue has 5,179 sources, 274 registrations and 29
individual reviews with none stale. Registration is not proof of qualification.

Each main stack has at most three containers: 1 CPU/512 MiB app, 0.5 CPU/512 MiB
MariaDB and 0.25 CPU/384 MiB reporting PostgreSQL. Swap equals memory, PID caps
are 128, init is enabled and published ports bind loopback. The control uses two
containers. All 132 main OOM/PID snapshots are zero; all 55 attached main objects
are individually absent afterward. Two unrelated connector containers appear
sequentially and are removed; maximum observed global inventory is four,
while work containers never exceed three. No unrelated images/volumes are pruned.
Final container inventory is empty and the exclusive lock is free before the
separate one-container staged diagnostic receives the lane.

This qualification uses macOS Docker Desktop's measured `host.docker.internal`
callback route. Linux-host routing, other PHP/database releases, earliest
affected core releases, TLS/proxies, multisite, external caches, other command
payloads and the staged PHP path remain unqualified.

The immutable 42-entry checkpoint is
`/Users/dwelch/.codex/reports/wordpress-batch-rce-qualified-checkpoint-20261117`,
manifest SHA256 `ec7beeef6eec6738d2f84ce34d07a49e539841a45eb17f6eeb7b6cd77efe2706`.
Its complete file set and every byte were independently rehashed, together with
23 referenced seals containing 2,605 entries. Original failures, intervention,
native controls, full result/console logs, source snapshots, reporting, resource
checks and cleanup receipts are retained. Publication CI is separate evidence;
the previous SQLi checkpoint's terminal results are in the
[publication follow-up](VERIFICATION-20261117-publication-followup.md).
