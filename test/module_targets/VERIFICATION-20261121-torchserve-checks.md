# TorchServe native YAML boundary and actual checks

Two new profiles pass **5/0/0** after independent native Java, vendor YAML and
real MAR controls. A confirmed version-check repair changes the actual module's
0.8.2 result from Appears to Safe. Repeated AutoCheck refusal passes on one
selected console object. **Owner exploit/session delivery remains unqualified.**

The fourteen previous profiles retain 48 cases and twenty-two used/closed
sessions with unchanged declared inputs. The latest sixteen stated profiles
therefore have **53 qualified cases**, 188 current declared inputs and 88 zero
memory/PID event captures. This adds one owner in a checked runtime path, two
profiles and five cases: **322 runtime owners, 686 profiles and 4,828 historical
functional cases**. These counts describe covered paths, not complete modules.
The broader inventory remains incomplete; no PR is created.

## Native controls and the confirmed fault

Both recipes use official pinned Linux amd64 CPU images, the vendor entrypoint,
UID 1000 (`model-server`) and the installed JDK. The supplied configuration
reduces resource-related thread/queue sizes and retains security defaults.
`vendor.json` records image digests, actual JAR fingerprints and Java versions.
The application JAR must match before and after every accepted profile.

Each profile compiles harmless source with the image JDK. Independent direct
construction and ordinary remote ServiceLoader loading must create one exact
UID-1000 proof each. The installed `ArchiveUtils.readYamlFile` then parses a
plain map and the unsafe global-tag chain. Real HTTP registration downloads
both MARs; physical archive bytes must equal the hosted bytes. Listing and
unregistration provide genuine application controls.

| Image | Native unsafe YAML / MAR outcome | Original actual module check | Repaired actual module check |
| --- | --- | --- | --- |
| 0.8.1, Java 17.0.7 | Constructor executes, then ClassCastException / HTTP 500 | Appears | Appears |
| 0.8.2, Java 17.0.8 | Global tag rejected, no constructor proof / HTTP 200 | Appears | Safe |

On 0.8.1 the physical HTTP proof belongs to the existing TorchServe JVM. The
500 response occurs after execution. The model is absent from the registry;
DELETE returns 404 and leaves the downloaded MAR. The native fixture records
that footprint and explicitly removes its exact archive. This is fixture
recovery, not qualification of module cleanup. On 0.8.2, plain and remote Java
positives still work, while both unsafe paths produce no proof. The application
catches the YAML parser rejection, so registration returns 200; normal
unregistration removes that archive. HTTP status alone establishes neither
execution nor safety.

The [vendor release](https://github.com/pytorch/serve/releases/tag/v0.8.2)
and [advisory](https://github.com/pytorch/serve/security/advisories/GHSA-8fxr-qfr9-p34w)
identify 0.8.2 as fixed; its SnakeYAML update rejects this chain. A warning about
permissive model URLs does not imply that default model downloads are denied.

The module compared against **8.0.2**. The isolated fix changes only that literal
to **0.8.2**. Eight focused unit cases cover the captured releases, neighboring
version boundaries and existing detection fallbacks. The same source suite
changes from **15 raw examples / 3 expected failures** to **15/0**, including
seven existing support examples. Neighboring versions are unit boundaries,
not additional image qualification.

## Maintained replay and cleanup

| Profile | Examples / failures / pending | Functional seconds | Scope |
| --- | --- | --- | --- |
| [torchserve_check](torchserve_check/README.md) | 2/0/0 | 51.69 | Native vulnerable controls and actual Appears check |
| [torchserve_fixed](torchserve_fixed/README.md) | 3/0/0 | 25.96 | Native fixed controls, actual Safe check and repeated refusal |

Passive traces retain original requests, responses, check reasons and source
paths. Both fixed AutoCheck attempts issue only the API-description GET. They
never enter the production exploit body, generate a MAR or start the class-loader
service. No Framework sessions or jobs remain.

The first runtime frame also passes 5/0. Self-review then finds a top-level
environment-variable lookup that breaks excluded spec discovery. Its original
dry run has one outside-example error. The corrected guard passes excluded
discovery without Docker configuration; the final two-profile replay above
passes with current inputs. The original passing frame, discovery failure and
original module false positives remain retained separately.

Stacks run serially, with **one capped application container** at a time:
1 CPU, 1536 MiB memory/equal swap, 256 PIDs and loopback-published ports.
All phases use explicit namespaces and the shared lock. Each stack and native
HTTP source closes immediately after use, including failures. Agent initialization
also creates two unused tool helpers; both exact IDs are removed under the
user's explicit all-unused-containers cleanup instruction.

All **sixteen new Docker objects** and **440 current/prior recorded objects**
are independently absent. The full global inventory has **zero containers,
including stopped containers**. No owned ephemeral network or volume remains.
Images and build caches are not part of these object counts.

Five changed/new Ruby files pass RuboCop. Module tidy, documentation tidy,
Python parsing and both Compose configurations pass. The module document's
original **1,202-byte Scenarios tail** remains unchanged, SHA256
`c5f64ba30d552d3cfd015c61418d31c3dee55f6c26be1adf3690d8db993aeeaf`.
Automated evidence does not supply human Scenarios.

The final immutable capsule `torchserve-checks-maintained-20261121T072823` under
`/Users/dwelch/.codex/reports/` contains 147 files: frozen inputs, complete
runtime captures, raw proof/HTTP records, audits and cleanup identities. Its
SHA256 manifest is
`8f3ed0fc1cdb9d9689ccc181baa92dcb91b1379cee32881edf1a78bea7653700`.
Original native vulnerable/fixed capsules and the first passing frame have
separate manifests. Publication binds committed blobs separately.

## Self-review and remaining work

**Summary:** The real fixed-release false positive is repaired and gated by
working native prerequisites on both sides of the boundary.

**What looks good:** Independent loading, exact physical proofs and archive
bytes distinguish Java readiness, parser denial and post-execution HTTP errors.
The actual console check and repeated refusal agree with those controls.

**Concerns:** Java owner sessions, normal payload selection, repeated execution
and module artifact cleanup remain unqualified. The native partial-registration
MAR footprint needs investigation during actual owner testing. Other versions,
deployments and the broader valuable-module inventory remain incomplete.

**Suggestions:** Calibrate the normal Java Meterpreter JAR independently before
running the owner. Verify actual Spawn behavior, PID/socket lifecycle, original
session reporting, repeated selection and physical artifact cleanup. Preserve
the previous Calibre/PHP Meterpreter/Ignition/Laravel investigations.
