# GeoServer container targets

These profiles exercise GeoServer version checks, Unix command delivery and
XXE file reads against pinned official releases. Run from the repository root
with Docker and Compose available. The guarded runner refuses existing
containers or a resolved plan above five containers, then runs one project at
a time under a shared lock:

```sh
nice -n 10 bundle exec ruby tools/dev/run_guarded_module_target_tests.rb geoserver_2251 geoserver_2252 geoserver_2256
```

Each profile declares three services: one GeoServer (1024 MiB, 0.9 CPU), canonical
Framework (768 MiB, 1 CPU), and the reused genuine Apache frontend (96 MiB,
0.1 CPU). The total is 1888 MiB and 2 CPU. The native gate checks the resolved
configuration, actual Docker limits, health and OOM state. The JVM requests
`-Xms128m -Xmx512m` and one active processor
through the image's `EXTRA_JAVA_OPTS`. All selected official images are amd64;
emulation and other architectures are unqualified. Compose readiness is bounded
at 120 seconds; the cached canonical build has a separate 1800-second ceiling,
and functional tests have a 600-second bound. Only Apache publishes a random
loopback port; GeoServer and Framework share an internal network. No external
database, optional extension, custom GeoServer JAR or Internet callback is needed.
The fixture uses the vendor's bundled demo data.

| Profile | Cases | Official image manifest digest | Expected branch boundary |
| --- | ---: | --- | --- |
| `geoserver_2251` | 6 | `sha256:c210398100dcefdb3de3a7ebe7d1c5068aa92ce6e490aebdeaa3c51a79c1eb57` | Both affected |
| `geoserver_2252` | 2 | `sha256:08a08222093d5575282a02f4182ce2519fe6fad9ad7b0b4c2a293ef43793d5bc` | RCE fixed; XXE affected |
| `geoserver_2256` | 2 | `sha256:e1de9b20625f7ed1b2bc0aeb2b9eed2a28249d8e833f00e0f8e35e4ace1b5e64` | Both fixed |

Pins were selected from official registry manifest/config metadata. The
[RCE advisory](https://github.com/geoserver/geoserver/security/advisories/GHSA-6jj6-gm7p-fcvv)
fixes the selected branch in 2.25.2; the
[XXE advisory](https://github.com/geoserver/geoserver/security/advisories/GHSA-fjf5-xgmq-5525)
fixes it in 2.25.6. Other branch boundaries are outside this corpus. The Compose
files select published [official images](https://github.com/geoserver/docker)
with the runtime supplied for each selected release.

## Verification notes

On 2026-11-10, the standalone 2.25.1 native gate passed 21 recorded CLI/inspection
calls and 10 HTTP requests. It proved ordinary WFS/WMS behavior, frontend policy,
a fresh command marker and exact XXE text. All three services were healthy with
the declared HostConfig and cgroup v2 limits, no OOM kills, and a live 512 MiB
maximum / 128 MiB initial JVM heap. Framework only slept; no console, metadata
build or module action ran. The cold pull, cached build and readiness together
took 545.612 seconds; the 120-second readiness bound remained unchanged. All
three owned containers, two networks and one volume were removed by exact ID
and label audits, with an independently empty container inventory afterward.
One append was observed for the native request; it does not prove exactly-once
execution for other requests or feature types.

Module qualification comes from a complete runner result: exact 6/2/2 examples,
zero failures/pending/load errors, matching current input hashes, genuine native
controls and owned teardown. The ordinary invocation reruns its native controls
for each profile. Native success alone is not a module result. Retain each run's
`result.json`, `rspec.json`, input maps and raw artifacts when assessing coverage.

The ten selected cases are:

1. Affected RCE version check and quiet command with an empty marker file.
2. Exact command bytes through an authenticated application prefix.
3. Rejected Apache credentials, without command artifacts or false XXE loot.
4. Exact ordinary UTF-8 text obtained through XXE into fresh local loot files.
5. Missing and empty files, without false loot.
6. Unrelated genuine Apache, without a positive check or file read.
7. Fixed RCE version check and the ordinary forced module execution path.
8. XXE remaining available after the RCE branch fix.
9. Fixed RCE check and forced module execution on 2.25.6.
10. Fixed XXE refusal with a working native WMS control.

Every case repeats twice. The missing/empty case repeats each input twice.
The native gate first checks REST version, JAR hashes, Java/process identity,
actual limits/health, one real WFS feature and a genuine WMS PNG. It uses the
[supported WFS REST configuration](https://docs.geoserver.org/stable/en/user/rest/api/services/)
to set `maxFeatures=1`, with a real GetFeature readback. That setting alone
does not establish GetPropertyValue evaluation multiplicity. An independent
append script and handcrafted WFS request observe native execution/refusal;
a handcrafted XXE request compares disclosure against actual target bytes.
Frontend accepted/rejected Basic requests and unrelated Apache are independent
controls. Native setup errors are not module failures.

The unchanged modules use different path contracts: the RCE module appends
`geoserver` to `TARGETURI` (root `/`, authenticated prefix `/auth/`); XXE uses
the application path itself (`/geoserver`, `/auth/geoserver`). Authentication
here is Apache HTTP Basic, not built-in GeoServer RBAC. The authenticated RCE
case disables AutoCheck so it tests that delivery path without claiming UI
redirect/version discovery through that prefix.

Main producer/request methods are unchanged. The RCE module shuffles real
feature types and probes `whoami`; its HTTP 400/ClassCastException oracle alone
does not prove execution. Fresh exact marker bytes and a separate append count
are required. Counts are observations for each request, not an exactly-once
promise. Fixed module runs can stop during that discovery probe before sending
the operator's CMD; native marker refusal independently tests the fixed path.

`input_audit.rb` records actual returned XML/URI and selected-owner request
arguments/response-body bytes, delegating once without payload regeneration.
These are **RETURNED-XML/URI and REQUEST-ARGS/RESPONSE-BODY**, not PCAP or socket
captures. Request body bytes must match the actual returned producer string.
Raw response bodies are retained even though console tracing prints headers
only, avoiding an expected ClassCastException body colliding with the shared
console exception guard. XXE XML/SLD versions, WMS versions/formats/bounds and
feature-type order remain randomized by the owners. Two repetitions do not
exhaust those combinations; a rejection is preserved for native investigation.
Before cases, the recorder must install into the actual selected module classes,
write its empty artifact file, and find the Unix Command target with the generic
command payload in the real compatibility catalog. Actual calls must yield
request records; positive producer bytes must match one actual request argument
and the intended command/file path. A missing calibration record is a fixture
diagnostic, not a module verdict. Target marker/loot proof remains independent.

Each command is independently executed with the native shell, captured and
removed before Framework execution. Quiet commands require real file existence,
not empty output alone. Per-run cleanup restores the exact owned filename
inventory and unchanged native text/empty fixtures, checks no sessions/jobs,
and retains local loot as evidence. Runner teardown owns only its fresh project,
volume and network. The guarded source is included in guarded input maps.

Pending: sessions and fetch delivery, Windows, built-in roles, TLS, other
release branches, binary/XML-sensitive text, leading/trailing whitespace and
quote/backslash ingress. These fixtures leave production owner code and existing
human Scenarios unchanged. Successful commands or text reads must not be
presented as qualification of these omitted paths.
