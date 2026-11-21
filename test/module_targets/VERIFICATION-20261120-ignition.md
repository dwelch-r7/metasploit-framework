# Ignition native commands and debug-disabled controls

The maintained set passes **27/0** across four profiles in two serial phases.
Ignition adds one runtime owner in covered paths and two qualified profiles with
**9/0**, reaching **317 runtime owners, 669 qualified profiles and 4,773 historical
functional cases**. The eighteen Ninja/InvoiceShelf regressions add no duplicate
campaign counts. The broader goal remains active; no PR is created.

## Genuine target and native gates

The fixture pins Vulhub's Linux amd64 manifest
`sha256:afd50843b9b5dd42418e4abbb2dc0607ff80aa6a68a4722dc4832563c77a7ad5`.
Its `8.4.2` image tag contains actual Laravel **8.26.1**, PHP **7.4.15**, Ignition
**2.5.1**, Guzzle **7.2.0** and PhpOption **1.7.5**. Thirteen installed source
hashes pin the real classes, bootstrap, configuration and routes. The normal
Apache service runs the unmodified application; startup supplies the initially
missing writable log. Commands execute as UID 33. The
[upstream image recipe](https://github.com/vulhub/vulhub/blob/master/base/laravel/8.4.2/Dockerfile)
and [original research](https://blog.lexfo.fr/laravel-debug-rce.html) identify the
fixture and vulnerable component; installed runtime observations establish these
specific versions.

Before every owner command, the installed PHP classes and PHP's own PHAR writer
produce an independent archive. Generation disarms the local destructor and must
leave the proof absent. Genuine HTTP requests write encoded bytes to the log,
convert it into the exact generated archive and trigger it. Exact file bytes and
UID 33 establish execution. Only the archive-generation CLI uses
`phar.readonly=0`; HTTP configuration and vendor sources remain unchanged.

The debug-disabled control uses the same sources with `APP_DEBUG=false`. Its
exact archive first creates a UID-33 proof through PHP's CLI; the gadget then
raises its observed post-execution `LazyOption` return-type exception (exit 255).
After proof removal, the same archive receives HTTP 404 without executing. Both
native controls repeat before the owner is assessed. Normal AutoCheck then
returns reason-bearing Safe results twice and withholds all owner exploit/PHAR
methods on the same selected console object.

## Confirmed command-byte repair

The owner placed commands in PHP's escape-decoding uppercase `S` scalar format.
Captured shell backslashes made three real command families fail after their
independent native controls passed. Metadata was already ASCII-8BIT and
byte-sized. The defect was escape interpretation, rather than Unicode character
counting.

The repair snapshots `payload.encoded.b` once and stores that command in a
literal lowercase `s` scalar using its byte size. Escaped private-property `S`
fields, metadata, targets and payload defaults remain unchanged. Native PHP
rejects the three captured failing metadata blobs while accepting four ASCII/
explicit-log blobs; the candidate's six actual metadata cases all parse.

Identical focused spec/fixture inputs change **14/6 to 14/0** (seven serialization
examples plus seven support cases). The root source run also passes **14/0**.
With only the module changed among the original profile's **23 recorded inputs**,
the genuine owner replay changes **7/3 to 7/0**. Unit fixtures come from native
PHP serialization and include captured commands, literal hex-looking escapes,
Windows path bytes and repeated use; Windows runtime execution is unqualified.

## Maintained qualification

| Profile | Examples/failures/pending |
| --- | --- |
| `ignition` | 7/0/0 |
| `invoiceninja` | 10/0/0 |
| `invoiceshelf` | 8/0/0 |
| `ignition_debug_disabled` | 2/0/0 |

The main profile checks the real debug/version page, automatic and explicit log
selection, exact ASCII/Unicode/LF/CRLF/quoted bytes, repeat execution and configured
missing-log denial. Ten successful owner commands follow eleven native full-chain
controls. The artifact audit verifies **21 positive physical file observations**,
matching exact bytes and UID 33. Ten read-only post-owner log-zero observations
precede subsequent native controls, preventing those controls from repairing an
owner's cleanup before its repeat is assessed. The deliberate missing-log case
asserts its expected UID-33 error log and withheld command; the diagnostic remains
until the disposable stack is removed.

The first serial phase passes the main and shared regressions (**25/0**). Its
debug-disabled native controls pass, but the owner example is pending because a
scalar readiness flag did not persist across RSpec example instances. That
attempt remains unqualified. Moving only that flag into the existing shared
receipt hash gives a fresh **2/0** debug-disabled replay. All executable inputs
for the three previously successful profiles still match; the final combined
provenance contains **68 current frozen inputs**. Each of the
four latest qualifying profiles has no pending or outside-example errors.

All **18 qualified memory/PID event captures are
zero**. Including the retained pending stack, the two phases provide 22 zero
captures and **13 exact Docker object removals**.
The test namespaces peak at **two concurrent containers**, with stacks run
serially. Ignition needs one app (1 CPU, 512 MiB/equal swap, 128 PIDs); only the
Ninja regression adds its existing capped database service.

The final global audit also removes six unused GitHub/AWS MCP helper containers
that appeared outside the test namespace during agent/tool initialization. The
shared Docker policy now requires global inventory checks after initialization,
counts helper containers in the resource budget, and requires each delegated
agent to return exact cleanup evidence. The final running/stopped container
inventory is empty; all **229 recorded Docker objects**
from the current and prior investigation phases are independently absent. No
owned ephemeral network or volume remains.

Seven new/changed Ruby helper/spec files pass RuboCop; the readiness-only spec
correction passes separately. Module RuboCop exits 1 and msftidy exits 2 solely
for the same two inherited default-payload offenses at lines 40/49, with zero new
offenses. Documentation tidy retains the same five original warnings, with zero
new diagnostics; historical Scenarios formatting is preserved. The module's
human Scenarios body remains 1,218 bytes with SHA256
`383c03e0a902ccdddb3526949d246a70ea22d9120b8acfd465b08dc35cce9d75`.

## Retained failures and limits

The original 25-example baseline contains three owner command failures and an
invalid denial-cleanup expectation; Ninja/Shelf pass 18/0. A second original
7/4 attempt adds read-only owner cleanup checks and retries the native reset,
which still retains 8,192 bytes from the deliberate missing-log error. Correcting
the denial contract gives the final original **7/3** baseline without changing
its native execution gates. The reset symptom remains captured for investigation
of broader pre-existing-log states; its cause and wider impact are unverified.

A private diagnostic filename also shadowed Python's standard `inspect` module
while formatting errors, causing two extra isolated inspections. Renaming it,
guarding execution behind main and verifying safe import resolves that helper
issue. All three inspection containers are removed; no module verdict or
campaign count derives from those inspection runs. A case-sensitive cleanup
assertion is retained alongside its independent exact-ID absence check.

Default/session payload delivery, genuine patched Ignition packages, Windows,
other releases and broader pre-existing-log conditions remain unqualified. No
private payload runtime or transport proxy substitutes for the normal owner.

## Retained evidence

Local capsules preserve complete logs, snapshots, native/owner observations,
input digests, independent audits and exact resource receipts. The initial
pending phase is explicit; the maintained capsule links it and contains the fresh
negative replay plus per-profile current-source provenance.

| Capsule | Files | SHA256 manifest |
| --- | --- | --- |
| `ignition-maintained-20261120T235032` | 79 | `dabc5200fa1dd9b92306a0962374662e1dbed38f7038e6fcbc6cd49324763f2b` |
| `ignition-candidate-pending-control-20261120T233825` | 283 | `31034d5a9fbd531245ed8d370dd3f1bc6fd9baa3bbd9601090087b336bb7a8fe` |
| `ignition-final-original-owner-20261120T233114` | 117 | `3076c525ca3f41368783462630c9c8564495d0c7946561a486b0433f18a44e73` |
| `ignition-original-owner-and-regressions-20261120T231022` | 226 | `f2de827c0023aa9dfc2075a34431d15a6d1181bf92c5209032807c75911f7ab8` |
| `ignition-original-read-only-cleanup-20261120T232151` | 128 | `f64c14cb5ed4c85a7a0289733e6adb15e4a9731f5b5870faf4012e7546a73e8c` |
| `ignition-native-chain-20261120t230401` | 84 | `49bda8b6a694cc36d4770d8ebcdd40b3fed40afdfe478565519f39b16d14d623` |
| `ignition-debug-disabled-native-20261120t232855` | 57 | `ecee3e0ffa5cabc2cd3bc18adff578e94f1d9f25d26af2984601f69e10c7991a` |
| `ignition-inspection-import-correction-20261120T231937` | 23 | `564d184d6a9ddde785577e3da4c9575cebdc0a9afe0afd28fb9bad808e79c5bc` |
| `ignition-command-serialization-20261120T233201Z` | 56 | `59f23b5256bee60fe7df9563596c1b7723f9021b5689b9041f6f71cb49be7a79` |

## Self-review

**Summary:** The confirmed command-escaping repair passes focused and native
before/after checks; two new profiles qualify the covered command/configuration
paths. The full original module-inventory objective remains active.

**What looks good:** Genuine installed classes, native archive bytes, physical
UID/file proofs, read-only owner cleanup and Safe method-withholding distinguish
working execution from HTTP status or console banners. Existing shared consumers
pass their complete command profiles.

**Concerns:** Two inherited module lint offenses remain. Session/default delivery,
patched packages and broader pre-existing-log states need separate qualification.
The observed error-log reset symptom is retained without an unsupported cause.

**Suggestions:** Investigate that log state, then extend real default/repeated
sessions and patched-package controls with independent native gates. Continue
other valuable container-feasible owners and check global helper-container use.
