# Legacy Selenium Firefox execution

This opt-in profile reuses the shared Firefox execution controls and tests on
stock digest-pinned Grid 3.141.59 / Firefox 92.0.1, Linux/amd64, UID1200.
One target runs at 768 MiB / 0.5 CPU / PID512, with init, equal memory/swap and
128 MiB shared memory. There are no mounts or target source replacements.
The real Framework console runs on the host; WebDriver binds to loopback.

```sh
bundle exec ruby tools/dev/run_guarded_module_target_tests.rb selenium_greed_firefox3
```

Run both protocol generations serially with:

```sh
bundle exec ruby tools/dev/run_guarded_module_target_tests.rb selenium_greed_firefox4 selenium_greed_firefox3
```

## Independent prerequisites and identification

Native DOM/JavaScript, shell MIME execution and browser deletion must pass before
owner calls and again afterward. The shared native client handles JSON Wire and
W3C response/session forms and records actual status/help responses, versions,
UID and cgroup observations. An independent single-container prerequisite has
already passed without any owner call. Registration alone is not qualification.

The legacy status says `Server is running`; its generic build fields alone do
not identify Selenium. The owner now also requires matching Selenium help-servlet
metadata. It reports `Detected` with the actual version, retaining unknown browser
availability. It does not upgrade passive detection to Appears/Vulnerable or open
browser probes during check. API-only deployments without confirming help HTML
remain Unknown and are not qualified by this fixture.

Explicitly select `BROWSER firefox` on this legacy service. AutoCheck permits a
Detected result and then runs that explicit choice. The discovered WebDriver API
prefix is reused for creation, navigation and deletion. The default automatic
browser choice is expected to reject unknown availability with NoTarget; this
does not claim that the real Firefox binary is absent. Root and `/wd/hub/` paths
are exercised; nested proxy prefixes have unit contracts, not native proxy proof.

## Requested cases and recovery

The shared spec requests seven legacy cases: manual check/command proof, repeated
Python Meterpreter, repeated Bash shells with AutoCheck disabled, repeated Linux
WGET-fetch Meterpreter, invalid-timeout rejection, automatic-selection refusal,
and genuine command execution from the server-root base. Python/fetch cases use
AutoCheck with explicit Firefox. Real APIs and native bytes/UID/PID observations
must agree, and each repeated console configuration starts after explicit
per-run recovery. Framework clones execution instances.

The [Grid 4 guide](../selenium_greed_firefox4/README.md) describes the common
session, channel, marker and artifact boundaries. Downloaded handler scripts are
recovered by the harness using actual observed script hashes, not claimed as
automatically removed by the production owner. Recorded session PIDs must exit
without operator signals; pre-existing files must agree within selected scopes.
The whole filesystem/process table and logs are not claimed unchanged.

The original false-NoResponse check, corrected owner-only replay, native
prerequisites and synthetic contract boundaries retain separate evidence. All
31 existing cleanup contracts remain unchanged. Final qualification requires a
passing aggregate, matching input hashes, native before/after controls and
successful container/network teardown. Other releases, Chrome/Selenoid,
authentication, architectures/platforms and transport loss remain unqualified.
Human module Scenarios are preserved.
