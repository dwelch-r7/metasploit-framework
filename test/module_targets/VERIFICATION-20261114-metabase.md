# Metabase release, bootstrap and setup-state boundaries

The covered paths of `exploit/linux/http/metabase_setup_token_rce` pass across
12 profiles and 11 genuine official release images. The cumulative record advances
to **247 modules qualified in covered paths, 319 profiles and 3,025 functional
examples**. This replay covers Metabase; earlier qualifications retain their
recorded inputs and evidence. The broader campaign remains incomplete. No PR
is created.

```sh
DOCKER_CONTEXT=default BUILDX_BUILDER=default bundle exec ruby tools/dev/run_guarded_module_target_tests.rb metabase metabase_fixed metabase_legacy_044 metabase_fixed_044 metabase_initial_042 metabase_configured_042 metabase_legacy_043 metabase_fixed_043 metabase_legacy_045 metabase_fixed_045 metabase_enterprise metabase_enterprise_fixed
```

| Profile | Version | Cases | Public calls | Real shells | RSpec duration | Result |
| --- | --- | ---: | ---: | ---: | ---: | --- |
| `metabase` | 0.46.6 | 15 | 30 | 4 | 206.55 s | Pass |
| `metabase_fixed` | 0.46.6.1 | 8 | 16 | 0 | 56.35 s | Pass |
| `metabase_legacy_044` | 0.44.4 | 10 | 20 | 2 | 96.21 s | Pass |
| `metabase_fixed_044` | 0.44.7.1 | 8 | 16 | 0 | 54.37 s | Pass |
| `metabase_initial_042` | 0.42.1 | 10 | 20 | 2 | 98.12 s | Pass |
| `metabase_configured_042` | 0.42.1 | 8 | 16 | 0 | 55.94 s | Pass |
| `metabase_legacy_043` | 0.43.7.1 | 10 | 20 | 2 | 96.29 s | Pass |
| `metabase_fixed_043` | 0.43.7.2 | 8 | 16 | 0 | 62.05 s | Pass |
| `metabase_legacy_045` | 0.45.4 | 10 | 20 | 2 | 135.21 s | Pass |
| `metabase_fixed_045` | 0.45.4.1 | 8 | 16 | 0 | 53.63 s | Pass |
| `metabase_enterprise` | 1.46.6 | 10 | 20 | 2 | 103.37 s | Pass |
| `metabase_enterprise_fixed` | 1.46.6.1 | 8 | 16 | 0 | 64.16 s | Pass |

Run `20261114T192501-f0eb06` and its original controller exit zero. All 113 cases
pass with zero pending cases and outside-example errors. The serial invocation
takes 1729.96 seconds including builds, startup and teardown.

## Native fidelity and setup state

The [recipes](metabase/README.md) pin official image digests and installed JAR
checksums. Every JAR matches the publisher's release checksum. Images keep their
original startup and normal API setup; no application route, owner behavior,
vulnerability, command artifact or session is simulated. Application and reporting
PostgreSQL databases use separate roles.

Independent controls verify exact versions and Java UID/PID/start identity,
complete core_user/setting/metabase_database records and real authenticated
administrator sessions where configured. Genuine H2 validation must write exact
Java NIO UTF-8 bytes on affected states. Wrong-token and protected-state attempts
must leave no artifact. HTTP 400 alone establishes neither execution nor protection.

The separate native pilots cover both fresh and configured states across all 11
versions. Fresh 0.42.1 executes the probe; normal setup clears its token and prevents
execution. Affected 0.43/0.44/0.45/0.46 and Enterprise 1.46 retain exploitable validation
after setup. The listed fixed releases retain a visible token but reject malicious
connection options before setup and initialized setup operations afterward.
Enterprise core behavior uses no license key or external provider; paid features
are outside coverage.

The [vendor advisory](https://www.metabase.com/blog/vulnerability-advisory) supplies
separate OSS fixes 0.43.7.2, 0.44.7.1, 0.45.4.1 and 0.46.6.1 with corresponding
Enterprise branches. Fixed JARs omit Clojure sources present in affected JARs;
reviewed 0.44/0.46 public tags do not expose the complete installed security patch.
Binary checksums and native observations establish provenance. Installed fixed
code is not claimed identical to public-tag source.

## Actual owner execution

All 226 calls use public check/run paths. Captured results contain 76 reason-bearing
Appears, 40 Safe and 72 Unknown codes. AutoCheck-disabled and incompatible-payload
attempts explain the remaining calls. Genuine health JSON, missing routes and
independently refused ports exercise expected failures without check exceptions.

Fifty-four finite command proofs establish exact ASCII/UTF-8 target bytes and
UID 2000. The main profile covers all three command-length residues used by the
base64 padding logic. AutoCheck guards, forced runs and disabled checks repeat
on each branch. Configured 0.42.1 retains a passive Appears version result; actual
exploitation rejects its absent token before any validation POST.

Fourteen genuine Bash/netcat sessions are opened, used and closed. Native marker
bytes, process UID/ancestry and real Framework session/database rows agree.
Remote shell exit precedes transport closure; process removal, closed_at, idle
jobs/sessions and application-record restoration follow. Netcat's randomized FIFO
must disappear before test cleanup. Operator-requested marker files are removed
by the test. Every case repeats from the same console configuration using normal
execution replicants. Focused contracts separately cover same-instance calls.

The generic Unix target rejects Linux-specific curl/wget Meterpreter fetch
payloads before any owner request. These negatives do not qualify Meterpreter
delivery. Other versions, editions, databases, licensed features and transports
remain untested; Enterprise native execution is covered only for the listed 1.46 pair.

## Source defects and test-environment failures

The original owner run passes 17 of 24 cases. Four genuine JSON-health checks raise
Msf::Exploit::Failed instead of returning Unknown. Fixed 0.44.7.1 is misclassified
Appears and receives two otherwise-guarded command attempts, producing three
additional failures. Independent affected/fixed controls and exact command
artifacts distinguish these owner defects from setup assumptions.

Source commit `2ed79db5da09c58afdbdacc898898241e4b5be94` adds the advisory's
OSS/Enterprise branch thresholds and returns reason-bearing Unknown for missing,
non-object or malformed bootstrap/version data and expected connection failures.
It preserves prerelease parsing through Rex::Version. The exploit body, payload
default and RPORT declaration remain unchanged. The identical focused suite gives
**54 examples / 26 failures original -> 54 / 0 fixed**, with explicit HTTP boundary doubles.
Native source execution is established separately above.

Earlier native harness failures include an SQL alias collision, H2 option
separators and a nested Unicode-escape oracle. An expanded replay separately
finds eight Ruby keyword-helper failures before dispatch and three Linux-fetch incompatibility
attempts before any owner request. These are not module failures. An old image's
bundled extractor rejects an authentic 0.42.1 JAR; a temporary checksum-verified
copy read with standard-library ZIP/CRC validation resolves inspection and is
removed afterward. Every failed attempt is sealed before changing inputs.

The user's Docker restart interrupts an intermediate corrected invocation after
23 passing cases. Those results and the cleanly interrupted setup are sealed;
the remaining 18 cases then pass. The final replay of 113 cases above uses the completed,
frozen inputs throughout and needs no equivalence exemption for those pilots.

## Static checks and limits

Strict RuboCop on all four new fixture/spec Ruby files, Ruby syntax, module-doc
tidy and diff checks pass. The focused spec of 54 cases also passes strict lint.
Whole-owner strict RuboCop still exits 1 with the same two original metadata
policies: ModuleDefaultPayload and ModuleDuplicateOption. Full msftidy exits 2
because it embeds those checks; its own module checks pass. No suppression or
unrelated default/registration change is introduced, and no whole-owner clean
lint result is claimed.

The prior published MCPJam head's CI finishes with 62 successful checks, one skip and one macOS Mettle
failure. Debug shows an intact single-quote echo request returning zero channel
bytes; cause remains unverified. That workflow runs upstream Framework `bea1fb0`,
not its fork trigger head. See [deferred evidence](DEFERRED.md#published-mcpjam-checkpoint-macos-mettle-empty-output).
This does not qualify the current branch through hosted Mettle CI.

## Resources, teardown and preserved evidence

Each profile resolves to three bounded containers on an internal network with
no host ports: target 1536 MiB / 1.5 CPU / 256 PIDs, reporting DB 256 MiB / 0.5 CPU / 64 PIDs,
Framework 768 MiB / 1 CPU / 256 PIDs. JVM heap is 768 MiB; DB data uses bounded tmpfs.
Profiles run serially under the shared max-five guard. Actual Docker limits,
zero OOM/PID-limit events and unchanged installed JARs are verified.

All 36 containers and 12 networks are absent after 85 exact identifier, project-label and global
queries; no named volume remains. Global container inventory is empty and the
shared lock is free. The seven additional native pilots separately pass 43 root
cleanup queries. Human Scenarios remain byte-identical, suffix SHA-256
`fb0d3fff989e38ef98486bd295b06835e28ccd143594a6395135b4988c473ea7`.

Local immutable reports under `/Users/dwelch/.codex/reports` retain raw processes,
inputs, native APIs, source observations, unit comparisons and cleanup checks:

| Archive | Files | MANIFEST.sha256 digest |
| --- | ---: | --- |
| `metabase-source-contracts-20261114` | 98 | `0e58ef38b4ce66ad045559fd083f5b91cf7417d45997cd442b6db143d8540b9d` |
| `metabase-native-modern-20261114` | 38 | `1e7989ecd8705d4255d90b5a73a0cfffb5f55c14bc3fdc36e7552c7b97df1eed` |
| `metabase-native-older-20261114` | 36 | `4c59ab2d7393f2fd25a14417fabf07c7b81760633d9f418a5b7d07d1caf0636b` |
| `metabase-additional-images-20261114` | 43 | `b47e65f6bda25527bd3b0246dced7982aa2872118e40d13978a3348d3ca17784` |
| `metabase-native-additional-20261114` | 110 | `d52c60ca7d56f624f202fda338ed7fbf8ce1ae6c86760b6560e49b7e47ce3367` |
| `metabase-original-owner-failures-20261114` | 257 | `8f121802eb781f76540d4e3407610821cbc5e5314acf98bfd9048d6f95cc408d` |
| `metabase-expanded-harness-contracts-20261114` | 291 | `72a7846452e6e3fd7c05b2ee861e6d0b9fe8b529cdf452a863033ffdf7c71bdc` |
| `metabase-docker-restart-20261114` | 203 | `5ad81746d7463f64a357e66480f24430f269183b954747b6740e124180b0ba2f` |
| `metabase-post-restart-20261114` | 175 | `08e503fde3b3d6411960b924cdbcb88a1843e1727e5401a5666da5b265e0ef79` |
| `metabase-image-inspector-unzip-20261114` | 11 | `34e7d941789c620df5018c1bee822946c2df30c0f014d604c3bb4720665b7cff` |
| `metabase-qualified-20261114` | 744 | `3eccdd7169719d9672ee3d759ad98ba2d75e00b79af5a20ea8c2b74e805a00cf` |
| `mcpjam-terminal-macos-ci-20261114` | 36 | `4a0ec69b5e0435b95bcaddd0df5b93513d2831f6e484334888d533cd1ed3a7a8` |
