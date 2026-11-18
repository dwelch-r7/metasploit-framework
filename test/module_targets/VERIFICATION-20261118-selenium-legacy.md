# Legacy Selenium Firefox execution and detection, 2026-11-18

Qualified a second profile for [exploit/linux/http/selenium_greed_rce](../../modules/exploits/linux/http/selenium_greed_rce.rb), adding **seven functional cases** and reaching **291 runtime owners in covered paths, 587 qualified profiles and 4,090 historical functional cases**. The final serial aggregate passes **7/0 legacy and 5/0 Grid 4**, CLI exit 0, zero pending/outside errors and successful teardown. The five-case Grid 4 regression, native prerequisites, source-only replays and units are not added again. The broader campaign remains active; no PR is created.

## Reproduction and independent prerequisites

```sh
bundle exec ruby tools/dev/run_guarded_module_target_tests.rb selenium_greed_firefox4 selenium_greed_firefox3
```

The [legacy guide](selenium_greed_firefox3/README.md), [Grid 4 guide](selenium_greed_firefox4/README.md), shared native/session controls and Compose definitions remain together in the repository, linked from the existing module documentation. The legacy target is stock `selenium/standalone-firefox:3.141.59@sha256:738eeec4eba6e44d0e5f0697e36b77b907e3c6fb647759a82fe47dec0d188abf`, actual image ID `sha256:d1f4408519cde5342baefc7dab7f39580409deb4264bcb34503d88ba2799b341`. Native observations establish Grid 3.141.59, Firefox 92.0.1, Python 3.8.10, Java 1.8.0_292, Linux/amd64 and UID1200. The existing pinned Grid 4.27.0 / Firefox 133.0.3 image retains actual ID `sha256:ed813a11c96d556ae0f2003684eecea8f4a88e40084c851d9ee772e44c144df4`.

Each target runs alone at 768 MiB / 0.5 CPU / PID512, init, equal memory/swap and 128 MiB shared memory. The real Framework console runs on the host, ports bind to loopback, and there are no mounts, privileged mode, custom target handlers or Docker socket access. All Docker/native/Framework/lint work remains serial. The image cache is reused without a new build.

An independent legacy smoke cohort passes a real DOM/JavaScript operation, shell MIME canary with exact bytes/UID, browser deletion and native artifact recovery, with zero owner calls. Its read-only seal has 25 entries. The shared client is then extended for genuine JSON Wire/W3C session forms, legacy status/session routes and version fields. Final controls run before/after each owning profile and record actual status/help responses; neither owner methods nor HTTP/session transports are doubled in functional tests. The optional optimized-archive reader remains a disclosed capture limitation rather than an owner failure.

## Confirmed detection defect and unchanged replay

Original source SHA256 `80833a15289f62c65c2a1c7fd9e693002d896eb6654b3907fa88861b1581a153` expects a Grid-branded message and advertised node/browser metadata. The real legacy service instead says `Server is running` and reports its release in the JSON Wire build fields. The owner returns Unknown with the false reason `No response from target`, although independent native controls and actual explicit-Firefox execution work.

Original run `20261118T061427-b32474` has **5 cases/one failure**, zero pending/outside errors. Only manual identification fails. Six real sessions across Python Meterpreter, Bash and Linux WGET-fetch Meterpreter operate and exit without signals; both fetched binary paths are already absent, and native before/after, selected recovery and teardown pass. This separates a detection failure from an unavailable target or generally broken execution path.

Fixed `20261118T063508-357ef7` passes **5/0**. Exactly **one of 57 inputs changes: the owner; all 56 spec/fixture/helper inputs remain identical**. Both cohorts use the same Docker 29.9.3 engine and Linux 7.0.14-linuxkit kernel. The fixed check identifies version 3.141.59; generic command proof, all six real sessions and complete selected recovery pass. Fixed source SHA256 is `8fc7c69dfefb6a61d48613ef83a3266439beb646c62535e32a7b3e0f10b9da17`. Both 92-entry raw cohort seals remain independent; no replay is counted as new qualification.

Legacy identification now requires successful JSON Wire status, a valid release and matching Selenium-specific help-servlet metadata. Generic build fields alone are rejected. The recorded upstream [status handler](https://github.com/SeleniumHQ/selenium/blob/e82be7d3584062a0d16af8d562d387e3d4855aa1/java/server/src/org/openqa/selenium/remote/server/handler/Status.java) and [help servlet](https://github.com/SeleniumHQ/selenium/blob/e82be7d3584062a0d16af8d562d387e3d4855aa1/java/server/src/org/openqa/grid/web/servlet/DisplayHelpHandler.java) explain those distinct schemas. Version validation uses Rex::Version while the private grid_version return remains a String. The discovered API prefix is reused for creation, navigation and deletion, preserving the operator's mount.

Check returns reason-bearing **Detected**, without inventing Firefox/Chrome availability or opening browser probes. Framework's actual AutoCheck branch warns and proceeds on Detected, so explicit Firefox can work with AutoCheck enabled. Automatic browser selection cannot choose from unadvertised legacy metadata and remains a documented NoTarget result. API-only deployments without confirming help HTML remain Unknown. This does not claim passive vulnerability proof.

## Focused contracts

The final identical-spec trio is **51/8 original, 51/0 fixed and 51/0 repeat**; the parent independently passes **51/0** after import. All have zero pending/outside/support examples and outside errors. All **31 existing cleanup contracts remain unchanged**. Twenty added contracts cover passive identification, actual AutoCheck behavior, unknown browser availability, root and nested mounts, String return shape, malformed/unrelated status/help/version data and existing Grid 4/Selenoid behavior.

HTTP, Framework, payload and UI are explicitly doubled in these contracts; real owner/JSON/HTML/profile behavior executes. Legacy status fields and help-page bytes match actual native captures. Proxy paths and negative variants are synthetic, not native proxy qualification. Initial 50-example and pre-style captures remain separate from the final comparable trio. Two test-only inverse-select lint findings were corrected, followed by rerunning that entire final trio. The read-only unit seal has 75 entries, manifest SHA256 `2302a8e1b633a88975907386015c4d576d2c3f029f405cf48ee9ba8e6c0ce1ca`.

## Final serial aggregate

Run `20261118T064743-9cef7e` passes **12/0**: legacy **7/0 in 207.5 RSpec seconds**, Grid 4 **5/0 in 283.0 seconds**. Both profiles have zero pending/outside errors and successful cleanup.

| Legacy case | Successful executions | Genuine sessions | Behavior |
| --- | ---: | ---: | --- |
| Manual identification and Unix command | 1 | 0 | Detected version, exact bytes/UID, browser released |
| Python Meterpreter and repeat | 2 | 2 | Explicit Firefox with real AutoCheck |
| Bash shell and repeat | 2 | 2 | Explicit Firefox, AutoCheck disabled on fresh configuration |
| Linux WGET-fetch Meterpreter and repeat | 2 | 2 | Explicit Firefox with AutoCheck; fetched files absent |
| Invalid Firefox timing | 0 | 0 | BadConfig before browser creation/command |
| Automatic browser choice | 0 | 0 | Honest NoTarget; no browser or canary created |
| Server-root base with explicit Firefox | 1 | 0 | Real API discovery, AutoCheck, command and deletion |

The legacy trace records seven owner checks, ten exploit entries, eight successful executions and six real sessions. The two other exploit entries intentionally reject configuration/selection. Native observation independently finds `/status` at the server root returns 404; the final root case genuinely discovers and uses the legacy API. The Grid 4 regression retains five checks, eight exploit entries, seven successful executions and six real sessions. Its advertised-browser/Appears behavior is preserved.

All twelve real sessions have native file bytes/UID and live PID identity proof. Meterpreter channel sets agree before/after. All recorded session PIDs exit gracefully without operator signals; Framework finishes with no sessions/jobs and browser lists are empty. Each profile repeats three console configurations; Framework clones execution instances. Shell metadata is Unix on the physical Linux target. Four native browser/handler pairs make **46** control HTTP requests, and all **16** OOM/PID-limit observations remain zero.

There are **18 selected download-scope recoveries**. Grid 4 requires removal of **seven** new UID1200 files matching observed owner-script hashes. Legacy recovery finds **zero newly retained files** in those scopes and removes none; this does not prove automatic cleanup of every possible browser artifact. Fifteen actual generated handler scripts are observed across both profiles. Whole-filesystem/process-table equivalence and unchanged logs are not claimed. Both target containers and networks are individually removed, with at most one work container at a time and no foreign removals. Both Docker contexts finish empty.

All **55 Grid 4 inputs and 57 legacy inputs**, a **58-file runtime union**, match the tested bytes. The read-only aggregate trace has **127 entries**, manifest SHA256 `2949e337cdcbe2eebc35c2dc2d4b17f6283ee3ea0b80d7db1297c7e560cd5f58`.

## Checks and remaining investigations

The root command case emits a FileDropper manual-cleanup warning for a generated `/tmp` path. Its existence and registration cause were not independently observed before teardown; the warning alone does not establish a retained file. The exact trace/path is preserved for follow-up, and selected-scope recovery remains distinct from that unresolved observation. The whole no-mount container is removed. Production automatic deletion of downloaded handler scripts is not established by harness recovery.

New functional Ruby passes syntax/scoped RuboCop, Python helpers pass AST syntax, both guarded preflights and module-documentation tidy pass. Owner/unit full RuboCop exits 1 and msftidy exits 2 with the **same three existing owner offenses**: redundant Platform/Arch and duplicate RPORT. No new/spec offenses remain; full owner lint is not green. Human Scenarios remain byte-for-byte identical: 3,977 bytes, SHA256 `59fa96b396c4026c4578a4fd0991ce5a24470177d3c4073a79dad5cd3ae6e585`.

Other releases, Chrome/Selenoid, authentication, architectures/platforms, real reverse proxies, API-only identification, transport loss and forced cleanup remain unqualified. The [deferred record](DEFERRED.md) retains the warning and these limits. Subsequent SMB test/report logs prove actual `dwelch-r7/metasploit-framework@ad6ed581953e35616057f4d969a4d403765b7f29`, with 20/0; those jobs do not invoke these opt-in module profiles. The prior GPG head's Linux Mettle timeout cause remains unverified. No PR is created; the broader campaign remains active.
