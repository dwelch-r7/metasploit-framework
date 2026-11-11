# Selenium browser file reads

Run the genuine vendor profiles serially:

```sh
bundle exec ruby tools/dev/run_guarded_module_target_tests.rb selenium_firefox3 selenium_firefox4 selenium_chrome4 selenium_edge4
```

Each profile uses one stock browser/Grid container (768 MiB, 0.5 CPU) and the
shared Framework console (768 MiB, 1 CPU). Only one browser session is opened at
a time. Official image/platform config digests are in [profiles.json](profiles.json).
The browser container permits 512 tasks, including threads. Its earlier 256-task
ceiling was reached during repeated legacy browser creation; native pre/post
controls reject any PID exhaustion. Memory and CPU caps remain unchanged.
Firefox runs headless; Chrome and Edge retain the vendor's virtual X display,
with VNC disabled. No browser, driver, Grid handler or file response is replaced.
Read-only text fixtures and an ordinary target-loopback Python HTTP server
exercise the file and HTTP schemes. Nothing targets the developer's browser.

The independent native client checks actual file bytes, browser DOMs, versions,
missing/unreadable files, active sessions and ordinary HTTP file serving before
and after module calls. The empty file must have a real empty `pre` element;
absence of that element is a failed read. UTF-8 fixture bytes include a BOM for
consistent browser decoding. The large file exceeds 32 KiB. Both direct target
reads and browser-rendered text are retained in the evidence.

Thirteen module examples per profile cover ready checks, repeated default
reads, six text/path variants, HTTP, repeated AutoCheck-disabled execution,
missing files, permission denial and native-proven refused connections.
After every module call, an independent audit checks for leaked browser
sessions. If a failed call leaks one, the audit records and deletes it to prevent
cascading failures, then the example still fails. A passing result must require
no such recovery. Application identity, files and all final cleanup are checked.

These profiles are registered tests; qualification requires actual passing
results, input hashes and native pre/post evidence. The affected source example
and protocol variants are documented in the
[module documentation](../../../documentation/modules/auxiliary/gather/selenium_file_read.md).
The pinned vendor setup source is
[4.27.0](https://github.com/SeleniumHQ/docker-selenium/tree/f353914db44470765311f2a42f302bf935e7428d)
and [3.141.59](https://github.com/SeleniumHQ/docker-selenium/tree/163cc7d75ad5f24694dc233db10b9dd1ea13aae4).
