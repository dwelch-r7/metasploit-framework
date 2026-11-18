# Selenium Firefox execution and browser cleanup, 2026-11-18

Qualified [exploit/linux/http/selenium_greed_rce](../../modules/exploits/linux/http/selenium_greed_rce.rb) with **five passing functional cases, CLI exit 0 and successful teardown**, reaching **291 runtime owners in covered paths, 586 qualified profiles and 4,083 historical functional cases**. Seven successful executions include six genuine sessions; one additional owning call intentionally rejects invalid configuration. Native prerequisites, source-only comparisons, pilot cases and unit contracts are not added again. The broader campaign remains active; no PR is created.

## Reproduction and independent prerequisites

```sh
bundle exec ruby tools/dev/run_guarded_module_target_tests.rb selenium_greed_firefox4
```

The [target guide](selenium_greed_firefox4/README.md) keeps the Compose fixture, native controls and functional tests together, linked from the existing module documentation. The stock vendor image is pinned to `selenium/standalone-firefox:4.27.0@sha256:b1292054ce909ccc474a6c59a475039aeb4adf77c1d77ab5a160185fa562948d`; its actual image ID is `sha256:ed813a11c96d556ae0f2003684eecea8f4a88e40084c851d9ee772e44c144df4`. Actual Grid 4.27.0, Firefox 133.0.3, Linux/amd64 and UID1200 are observed. One container is capped at 768 MiB / 0.5 CPU / PID512, with init, equal memory/swap and 128 MiB shared memory. The real Framework console runs on the host; WebDriver publishes only on loopback. There are no mounts, custom target request handlers, privileged mode or Docker socket access.

Before any owning call, an independent stdlib WebDriver client must load a real DOM and execute JavaScript. A separate benign shell MIME handler must execute a canary with exact native bytes/UID. Its standard 5-second page-load bound returns a genuine HTTP500 navigation-timeout response while code execution succeeds. Native DELETE must then free the only browser slot. These controls remove their own downloads/marker and run again after all owner cases. An optional Python ZIP reader cannot decode Mozilla's optimized archive; this limitation is recorded without treating it as browser or owner failure. Actual effective profile and browser behavior supply the prerequisite.

## Confirmed leak and source-only repair

The original owner SHA256 is `7838c36c0a5bff59335d402b73ea04f14f783fee0542cb00da032bf89f2bdd55`. On a native-working target, its command executes successfully and creates the exact `owner-canary` bytes under UID1200, but navigation and browser deletion hit HTTP deadlines. The actual WebDriver session remains and occupies the only slot. Thus successful code execution alone does not establish successful cleanup or immediate repeatability.

Docker service availability changed during the investigation, including daemon 29.9.2 to 29.9.3. After readiness returned, the comparison was repeated from the original source on the same 29.9.3 engine and Linux 7.0.14-linuxkit kernel. Fresh original `20261118T052739-fbb2fb` has **1 example/1 failure** with the native control passing before execution and the browser demonstrably leaked afterward. Its post-control is deliberately skipped because the only slot remains occupied; marker/Framework recovery and isolated stack teardown pass.

Fixed `20261118T053128-d4dbba` passes **1/0**. Exactly **one of 31 inputs changes: the owner; all 30 fixture/spec/helper inputs remain identical**. The same command bytes execute, browser deletion succeeds, native controls pass before/after, and selected recovery and teardown pass. Fixed source SHA256 is `80833a15289f62c65c2a1c7fd9e693002d896eb6654b3907fa88861b1581a153`.

The repair supplies a bounded Firefox page-load timeout in both existing capability forms and ensures deletion once a browser ID is acquired, including navigation failures. Advanced `FirefoxPageLoadTimeout` defaults to 5 seconds and must be positive and below the effective HTTP deadline. Deletion only reports success for HTTP200; expected transport/deletion failures remain visible. Profile ZIP, command/Python delivery, browser selection, targets, aliases and Chrome request builders are preserved. The shared deletion helper's status/error handling has synthetic contracts; Chrome execution remains unqualified here.

Focused real-owner contracts with explicit HTTP/Framework/payload/UI doubles change **31/16 original** to **31/0 fixed and 31/0 repeat**. The parent independently passes **31/0** after import. They exercise actual profile ZIP/data URI serialization, both timeout capability forms, option boundaries, absent/legacy IDs, deletion status/errors, navigation exceptions and payload-preservation paths. Native response projections disclose which fields are exact and which compatibility/error variants are synthetic. All canonical runs have zero pending/outside/support examples and outside errors. They do not qualify a remote browser or session.

## Preserved setup and observer failures

Initial native controls used an unestablished MIME type and timed out; another stopped at the optional archive reader before its handler test. Corrected native control `native-20261118T044811` independently passes the real browser and documented shell MIME path. These native cohorts have no owner calls and add no qualification.

Pilot `20261118T045609-5c3dc6` stops at Framework's legitimate FileDropper guard: the sessionless generic payload cannot clean files without explicit `AllowNoCleanup`. No owner exploitation occurs. The corrected canary alone permits that option and removes its exact marker. A pre-update owner leak cohort remains preserved alongside the fresh same-engine comparison. A resource refusal during the Docker outage starts no container or example.

The expanded session pilot first fails before owner calls because an assumed `command -v` line count does not match the actual shell. Independent `shutil.which` then verifies all four required executables. The next pilot passes actual command execution and browser cleanup, but a helper consumes native callback symbol keys as string keys before the first session-owner call. Both failures and successful cleanup are retained separately. Correcting that helper yields a sealed **2/0** pilot with two genuine Python Meterpreter sessions and complete selected recovery. Loader, profile-reader and initial lint-observer mistakes in unit preparation are also retained and excluded from canonical results.

## Final five-case aggregate

Run `20261118T055527-290ea5` passes **5/0**, zero pending/outside errors, in **281.2 RSpec seconds**, including native controls and recovery.

| Case | Actual executions | Genuine sessions | Selected behavior |
| --- | ---: | ---: | --- |
| Manual check and Unix canary | 1 | 0 | Exact native bytes/UID; browser released |
| Python in-memory Meterpreter and repeat | 2 | 2 | Auto browser/AutoCheck; real file/process/system APIs |
| Bash command shell and repeat | 2 | 2 | Forced Firefox; fresh configuration with AutoCheck disabled |
| Linux x64 WGET fetch Meterpreter and repeat | 2 | 2 | AutoCheck; both selected fetched executables absent |
| Timeout equal to HTTP deadline | 0 | 0 | Owning BadConfig rejection before browser creation/command |

A passive TracePoint observes five actual owner checks and eight exploit entries, including the intentional rejection. Seven generated handler scripts have independently verified hashes. All six sessions have exact native file bytes/UID and live kernel PID identity; four Meterpreter sessions also retain identical before/after channel sets. Shell sessions report Unix metadata on the physical Linux target. All six recorded session PIDs exit after graceful remote shutdown, with no operator signals; Framework sessions/jobs and browser slots are empty before the next call. Three console configurations are each repeated. Framework clones execution instances, so this is not a same-execution-instance claim.

The harness performs eight selected download-scope recoveries and removes seven new UID1200 files matching actual observed owner-script hashes. This is **harness recovery of Firefox's downloaded handler scripts**, not proof that the production owner removes them. Both fetched binary paths are already absent when checked. Repeats occur after explicit per-run session/proof/download recovery. Pre-existing files agree within the selected download scopes; all processes and the whole filesystem are not claimed unchanged.

Two genuine native browser/handler pairs make 18 HTTP requests. All eight cgroup OOM/PID-limit observations remain zero. At most one work container runs, with no unrelated container removals needed in these cohorts. The target container and its network are individually absent after teardown; both Docker contexts are empty. All **55** final inputs match the tested bytes. The read-only final trace seal has **90 entries**, manifest SHA256 `80993649db419847b91916d30a9f2271f05243d0c21fc0727c8b49fed8efb37f`.

## Checks and remaining scope

New functional Ruby files pass scoped RuboCop and syntax; the Python helpers pass AST syntax; guarded preflight, module-documentation tidy and whitespace checks pass. Owner/unit full RuboCop exits 1 and msftidy exits 2 with the **same three pre-existing owner offenses**: redundant top-level Platform/Arch and duplicate RPORT. There are no new final spec offenses. Full owner lint is not claimed green. Existing human-written module Scenarios remain byte-for-byte identical (3,977 bytes).

Other Grid/Firefox releases, Chrome, Selenoid, authentication, other architectures/platforms, transport loss, forced cleanup and automatic removal of Firefox handler scripts remain unqualified. Historical broad version claims in the existing module documentation are not expanded or revalidated by this single-version fixture. The [deferred investigations](DEFERRED.md) retain those limits. The [acceptance checkout record](VERIFICATION-20261118-acceptance-checkout.md) records the previous published GPG head's actual-source Linux Mettle file/reset failures and macOS success; the underlying timeout cause remains unverified, and those jobs do not invoke this owner. No PR is created; the broader campaign remains active.
