# Jetty file-read verification — 11 November 2026

The checkpoint is **199 qualified modules, 151 profiles and
1,617 passing functional examples**. The [Jetty lab](jetty_webinf/README.md)
qualifies `auxiliary/gather/jetty_web_inf_disclosure` for both CVE selections on
genuine affected/fixed 9.x, 10.x and 11.x targets. Confirmed CVE-selection and
fixed-release check defects are corrected. The broad module campaign remains
incomplete; registration alone is not a passing result.

## Genuine targets and independent controls

Six pinned official Jetty images run **9.4.38.v20210224, 9.4.43.v20210629,
10.0.5, 10.0.6, 11.0.5 and 11.0.6**. Their exact amd64 manifest/config digests
are in `jetty_webinf/profiles.json`. Runtime image layers match every vendor
layer prefix; the standard vendor entrypoint and command are retained. Only
ordinary ROOT/WEB-INF files and heap/thread limits are added. The default URI
compliance is unchanged and no request handler is patched. A separately pinned,
genuine Apache HTTPD 2.4.62 target supplies the unrelated-product negative; its
actual platform manifest/config/layers are independently verified too.

The [first advisory](https://github.com/jetty/jetty.project/security/advisories/GHSA-v7ff-8wcx-gmc5)
places CVE-2021-28164 in the two 9.4.37/9.4.38 releases, fixed in 9.4.39. The
[later advisory](https://github.com/jetty/jetty.project/security/advisories/GHSA-vjv5-gp2w-65vm)
fixes CVE-2021-34429 in 9.4.43, 10.0.6 and 11.0.6. The tests independently
exercise both selected URI encodings on every real target, including rejection
of the earlier CVE on a release affected by the later CVE.

Before owning calls, Python's standard-library HTTP client verifies the actual
root document, Server header, unprivileged Java process identity, direct ordinary
WEB-INF protection, both encoded-URI behaviors, and missing resources. Exact
response bytes are compared with independent direct reads of the deployed files.
The file set includes web.xml, short and empty files, UTF-8 content, binary data
with NUL/0xff, a multi-buffer file and a nested configuration path. These controls
repeat after all module calls; actual Java PID/start time and every file hash
must remain unchanged. Apache's normal document and parent process are checked
independently before and after its negative cases.

A separate Ruby standard-library socket control runs inside Framework's actual
network namespace with the console's UID/GID and requires ECONNREFUSED from the
same target bridge address/port 1 used by the module. It does not call Framework
transport or owning methods. No module, encoder or service method is stubbed in
the functional runs. Non-UTF8 console output is retained as Base64 alongside the
original raw transcript; file bytes are never transcoded for comparison.

Each profile runs **two containers only**. Jetty profiles total **1,024 MiB and
1.25 CPUs**: target 256 MiB/0.25 CPU/128 PIDs and Framework 768 MiB/one CPU/256 PIDs.
The Apache control totals **864 MiB/1.1 CPUs**, with its target limited to
96 MiB/0.1 CPU/192 PIDs. Swap equals RAM, privileged mode is disabled, and only
random loopback service ports are published. One project bridge is used. Profiles
run serially and are removed before the next begins.

## Complete source-current replay

Run **20261111T160840-6a452f**, source
`a5fd359f7cedbdb26ccb92bb7fdb9079aa18b3ff`, completes naturally with manager exit
zero. All seven independent live startup/resource observers terminate zero.
The first real console prompt/BOOT and two fresh metadata snapshots have no
manual first seed; later consoles reuse only the verified same-invocation cache.

| Profile | Examples/failures | RSpec seconds | Owning calls | Exact loot files |
| --- | --- | --- | --- | --- |
| 9438 | 12/0 | 69.696304 | 18 | 10 |
| 9443 | 6/0 | 20.185679 | 12 | 0 |
| 1005 | 12/0 | 20.740153 | 18 | 8 |
| 1006 | 6/0 | 21.487687 | 12 | 0 |
| 1105 | 12/0 | 21.952635 | 18 | 8 |
| 1106 | 6/0 | 29.835898 | 12 | 0 |
| unrelated | 2/0 | 25.302684 | 8 | 0 |

All **56 examples** have zero failures, pending or outside errors. They make
**98 ordinary console module calls**, including repeated checks and default-file
reads/refusals for both CVE choices, six exact file-body variants, missing-file
error handling with AutoCheck disabled, refused connections and an unrelated
real product. All **26 successful loot files** match actual target bytes.
Error responses, fixed versions and unrelated products produce no invented loot.

Independent controls make **290 actual HTTP requests** before/after the module
cases. All six Jetty roles also pass the correctly scoped closed-port controls.
Root checks all **66 current selected input hashes**, all owning records and
native file/process evidence. The actual Docker engine/context remain identical.
Forty-nine independent cleanup queries verify all fourteen exact containers,
seven exact networks, project-label inventories and the empty global container
list. No project volume survives.

The immutable final package contains **487 files**, SHA256 manifest
`54d80612f80ca469a6e92044f419953a31b2fae68923768591240c78f38cb911`. Identical bytes are hardlinked only within that
read-only package; source and original run files remain separate copies.

## Confirmed module defects and fix

The clean original-source reproduction uses run `20261111T155026-a4d883` on
10.0.5 and 10.0.6. Both native pre/post phases pass, with unchanged process/files
and no unsupported fixture options. The actual manager exits one. The results
are 12 examples/two failures on 10.0.5 and six examples/four failures on 10.0.6;
the six failed assertions represent related manifestations of the check defects.
Twenty-four actual module calls include eight byte-exact successful loot files.
Fourteen root cleanup queries leave Docker empty. Its 166-file package manifest
is `b49903a3978b75fcabca55ab06c4fd5dd47eee58b6b791a9091986d10eb4f592`.

Selecting CVE-2021-28164 on 10.0.5 still reports vulnerability to CVE-2021-34429;
AutoCheck then permits a request the real server rejects with HTTP 400. On fixed
10.0.6, inclusive upper comparisons incorrectly classify the patched release as
affected and allow both CVE choices to reach rejected requests. Jetty's 9.x
`.vYYYYMMDD` dates also sort as prereleases below the bare fixed version under
Rex::Version, requiring numeric-release comparison.

The fix selects the correct CVE range, uses exclusive first-fixed bounds,
compares numeric release components and preserves the full displayed version.
Passive affected-version matches return Appears. Recognizable unsupported or
malformed Jetty versions return Unknown; unrelated products remain Safe.
Options/actions, URI selection and run/file-loot behavior are preserved.
Worker commit `dbdff8cd3f1662334914baab8b813cf8de37eaf1` is imported as
`ada3524cfbe`. The identical focused suite has **46 examples/27 failures before
and 46/0 after**, with zero pending/outside errors. Real header captures have
verified origin hashes; additional boundary and malformed cases are explicitly
synthetic unit inputs. Root's normal repository invocation passes **53/0**,
including seven shared formatting checks. All 65 source-fix evidence entries
verify against manifest
`acfe39d0f2871b05e4a4ee079d73b98db39dc0ee455b97030640e8b382558c28`.

## Fixture failures retained separately

The initial run `20261111T153804-2d163f` has 56 failed assertions because the
helper supplies an unsupported ConnectTimeout option and rejects its warning.
All native pre/post HTTP/file/process controls pass across the six Jetty releases
and real Apache. These are fixture failures, not 56 module bugs. Its actual
manager exits one; all 49 root cleanup queries pass. The 461-file package has
manifest `82a60eb4e7bcbd0198f413effa4aaf241a87b950d4fdab04b283bbfb0edbf5ec`.
The clean reproduction instead uses the registered HttpClientTimeout option.

Review also finds that the earlier closed-port control probes host loopback 1
rather than the target container's port 1. That earlier result does not qualify
the target-port refusal path; it does not invalidate the separately captured
HTTP/version/file evidence establishing the CVE defects. The final replay uses
the corrected same-namespace/same-UID target-port control described above.
Neither earlier batch is presented as a complete qualified result.

## Review and remaining scope

**Summary:** Genuine target/native controls, both CVE options, repeated public
module calls, exact loot bytes and teardown qualify the tested file-read paths.

**What looks good:** Native setup failures, fixture defects, original module
failures and final acceptance are distinguished. Source hashes, actual terminal
statuses and native/owning evidence agree. Human Scenario text is preserved;
only its missing final newline is normalized in the lab-link edit.

**Concerns:** No new concern remains within this scope. The existing duplicate
RPORT warning remains (original line 53, fixed line 54); module msftidy exits two
for that same warning. Changed specs/helpers have no new lint findings; docs,
Python AST, whitespace and local links pass. Other releases, HTTPS/authentication,
custom applications/compliance, Unicode filenames and files outside this deployed
WEB-INF tree are not qualified by these profiles. Version-only checks do not
prove the target's actual URI configuration permits disclosure.

**Suggestions:** Continue the remaining valuable module queue. The current
inventory registers 201 sources, with 304 documented container hints pending,
sixteen individual reviews and zero stale reviews. The previously unqualified
Druid JS, Superset RCE and WordPress admin profiles remain unqualified. No PR is
created.
