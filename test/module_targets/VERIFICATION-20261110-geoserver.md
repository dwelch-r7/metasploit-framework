# GeoServer native targets, November 10

Two unchanged modules complete ten bounded cases across official GeoServer
2.25.1, 2.25.2 and 2.25.6. This qualifies the selected command and ordinary-text
file-read paths described in the [target guide](geoserver/README.md), rather than
all target, payload, authentication or data combinations.

```sh
nice -n 10 bundle exec ruby tools/dev/run_guarded_module_target_tests.rb geoserver_2251 geoserver_2252 geoserver_2256
```

## Results and attribution

| Invocation | 2.25.1 | 2.25.2 | 2.25.6 | Meaning |
| --- | ---: | ---: | ---: | --- |
| `20261110T162545-901f5b` | 6/1 | 2/1 | 2/1 | Original strict baseline; three fixture expectations assumed public version disclosure. |
| `20261110T165841-5ddb7c` | 6/0 | 2/0 | 2/0 | Corrected original-owner baseline; all native, recorder, target and teardown gates pass. |

Counts are examples/failures. The corrected profiles terminate naturally with
RSpec durations 160.381512, 64.339984 and 47.558811 seconds; seeds are 18221,
52322 and 28671. They have zero pending or outside-example errors and passing
cleanup. Each has 45 current input hashes, 51 in union. The guarded launcher is
included in those maps. First startup observes the real console prompt, returned
isolated configuration marker and two freshly generated metadata Hash snapshots
with 7,264 and two keys. Subsequent profiles use ordinary within-invocation
metadata reuse. No timeout extension, manual seed, retry or production repair
produces these results.

The original failures are not owning parser defects. Captured anonymous pages
have the correct About title and login controls, without the version panel. The
[pinned Java page](https://github.com/geoserver/geoserver/blob/2.25.1/src/web/core/src/main/java/org/geoserver/web/AboutGeoServerPage.java)
and [template](https://github.com/geoserver/geoserver/blob/2.25.1/src/web/core/src/main/java/org/geoserver/web/AboutGeoServerPage.html)
put that panel behind `getSession().isAdmin()`; the 2.25.2 and 2.25.6 sources
retain this policy. Administrative REST identity does not establish anonymous
UI disclosure. The correction changes only the common guide, family fixture and
acceptance spec: assert reason-bearing `Unknown`, then require
`AutoCheck=true ForceExploit=false` to block delivery. Actual request records
must be GET-only, with no produced exploit XML or fresh target/loot artifacts.
Separate `AutoCheck=false ForceExploit=false` cases exercise quiet command proof
and fixed-release discovery refusal. Original failures and all 51 original input
bytes remain sealed; authenticated UI version parsing is unqualified.

## Genuine outcomes and resource limits

The final native gates record 90 CLI/inspection calls and 24 HTTP requests
(21/10, 34/7 and 35/7). They prove application/version/JAR/runtime identity,
ordinary WFS/WMS behavior, actual command/file-read boundaries and independent
target bytes. Native RCE/XXE observations are true/true on 2.25.1, false/true on
2.25.2, and false/false on 2.25.6. Fixed marker absence is bounded observation,
not an inference from an HTTP status. Apache accepted/rejected Basic policy is
separate from built-in GeoServer RBAC.

There are 38 actual main console calls: 22, eight and eight by profile. Four
Framework commands are proven using real fresh target files, including two quiet
commands whose files exist with exactly zero bytes, and two authenticated-prefix
commands with exact nonempty bytes. Each command is independently executed and
removed through the native shell first. All four observed append counts are one;
this does not promise exactly-once execution for other inputs or feature types.
Four positive XXE calls produce four separate exact-byte local loot files. Missing,
empty, denied, unrelated and fixed inputs produce no false loot. Per-run target
inventory and the native text/empty files are restored; no sessions/jobs remain.

Calibration installs the recorder into the actual module classes, verifies the
Unix Command target and generic command compatibility, and requires an initially
empty writable record. Producer returns and request arguments match without an
extra payload generation. Actual returned response-body bytes are retained.
These are **RETURNED-XML/URI and REQUEST-ARGS/RESPONSE-BODY** records, not socket
captures or PCAP. The owners retain their randomized XML/SLD/WMS versions,
formats, bounds and shuffled feature discovery. Two repetitions do not exhaust
those combinations.

Only one three-container project runs at a time: GeoServer 1,024 MiB/0.9 CPU,
Framework 768 MiB/1 CPU and Apache 96 MiB/0.1 CPU, totaling 1,888 MiB/2 CPU.
Actual HostConfig limits, health and no-OOM facts are retained for all profiles.
The standalone affected-only native attempt additionally verifies live cgroup v2
limits and JVM maximum/initial heap 512/128 MiB with one active processor; it
uses sleep-only Framework and supplies no module result. Native gates and all
main requests use internal target networks; only Apache has a random loopback
published port. No external callback or new project dependency is introduced.

Independent final audits confirm all nine recorded containers, six networks and
three volumes absent by exact ID/name and ownership labels. Global container
inventory is empty after teardown. Historical Druid's 105 selected files and
2,867 retained ignored evidence files remain byte-identical. Both production
GeoServer modules and existing human Scenarios are unchanged.

## Retained evidence and gaps

The native-only attempt, original ten/three and corrected ten/zero invocation
are preserved in separate immutable exports under:

- `/Users/dwelch/.codex/reports/geoserver-native-2251-20261110-0bf55713`
- `/Users/dwelch/.codex/reports/geoserver-original-main10-20261110-448e8882efa5`
- `/Users/dwelch/.codex/reports/geoserver-final-main10-20261110-e92c31c631cb`

Each export includes a checksum manifest, raw observations, exact input copies
and independent audits. The original and final full runner invocations each
retain 145 regular files, including hidden metadata. Static checks select exactly
6/2/2 examples; acceptance-excluded discovery passes seven ancillary examples,
and both changed Ruby files pass syntax and RuboCop. Existing module-document
checks and unchanged recorder contract examples are retained separately from
runtime qualification. No full local suite was run.

Sessions/fetch delivery, Windows, built-in roles, TLS, other release branches,
binary/XML-sensitive text, leading/trailing whitespace, quote/backslash ingress
and authenticated-UI version parsing remain pending. Fixed RCE module calls can
stop at the native feature-discovery oracle before operator CMD delivery; native
marker refusal independently covers the branch boundary. Hard command proof is
required for positive execution; HTTP 400/ClassCastException alone is insufficient.
