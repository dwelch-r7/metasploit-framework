# BentoML container module tests

Run the real API and legacy runner owners against stock BentoML packages:

```sh
python3 test/module_targets/bentoml/prepare.py
bundle exec ruby tools/dev/run_guarded_module_target_tests.rb bentoml bentoml_runner bentoml_fixed
```

The launcher uses the existing host Ruby bundle and isolated console configuration.
It runs one fresh Compose project at a time and removes its containers and network.
Each profile has one nonprivileged UID1000 container, one CPU, 512 MiB memory/equal
swap, PID128 and init. A random loopback port exposes the service; native callback
routing is independently verified before starting payload handlers. RSpec has a
600-second bound; build, health and teardown have separate bounds.

## Versions and native prerequisites

| Profile | Genuine service | Version | Expected owner check |
| --- | --- | --- | --- |
| `bentoml` | Batchable Echo API | 1.4.2 | Appears |
| `bentoml_runner` | Legacy picklable-model runner | 1.4.2 | Detected |
| `bentoml_fixed` | Batchable Echo API | 1.4.8 | Safe |

The API [advisory](https://github.com/bentoml/BentoML/security/advisories/GHSA-33xw-247w-6hmc)
covers 1.3.4 through 1.4.2 and identifies 1.4.3 as fixed. The runner
[advisory](https://github.com/bentoml/BentoML/security/advisories/GHSA-7v4r-c989-xh26)
identifies 1.4.8 as fixed. This lab executes only the versions in the table.
BentoML 1.4.8 removes the public `start-runner-server` command and implementation;
that unavailable standalone runner is excluded from runtime-safe comparisons.

The pinned Python 3.12.12 linux/amd64 base installs 73 distributions through complete
hash-locked requirements. Only the BentoML distribution differs between releases.
The preparation command caches checksum-verified official wheels in ignored `tmp/`.
Before and after owning calls, native controls verify installed vendor Python files
against those wheels, version/UID and ordinary JSON/NumPy predictions. They exercise
pickle canaries, negative content-type/path controls and exact marker recovery.
The patched API must reject the selected pickle content type with HTTP415 while
ordinary predictions continue. Pickles are interpreted only in the disposable app.
The tiny service/model fixtures use actual vendor routing and serialization.

## Functional coverage and recovery

The vulnerable profiles execute both owner targets and five genuine session
families: staged Python Meterpreter, stageless Python Meterpreter, Python command
shell, Bash and Linux HTTP-fetch Meterpreter. Each family repeats with AutoCheck
disabled and the same console configuration. Meterpreter uses real file APIs and
checks channel recovery; independent native reads verify exact bytes and UID1000.
Kernel TCP state and descriptor ownership are captured around public shutdown.
Fetch artifacts, selected remote processes, proof files, local sessions/jobs and
OOM/PID-limit events are checked. Recovery scope is socket/file state and repeat
execution. Fork-child zombies may persist until full container teardown.

The API also covers explicit and unrelated ENDPOINT values. The unrelated endpoint
case establishes absence of execution; the current owner does not classify its
HTTP404 as an exploit failure. Both owners check an independently unused port.
The fixed API covers real AutoCheck refusal and forced nonexecution for both targets.

A retained parent descriptor originally breaks staged-session recovery. The shared
Python TCP stager now closes its own socket when downloaded-stage execution returns
or raises, preserving the forked child's descriptor. A 65-input replay changes only
that library: strict staged/inline comparison improves from 10/2 to 10/0, with native
predictions and teardown passing. Four real-TCP unit regressions also reproduce the
original failure. The [verification record](../VERIFICATION-20261118-bentoml.md)
contains measured results, provenance and original failures. Human module Scenarios
remain unchanged. Other versions, architectures, TLS/proxies and transport loss
remain outside this lab's qualification.
