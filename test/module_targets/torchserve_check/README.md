# TorchServe native controls and version check

```sh
MODULE_TARGET_NAMESPACE=torchserve-local bundle exec ruby tools/dev/run_guarded_module_target_tests.rb torchserve_check torchserve_fixed
```

Run serially. Each profile uses one official Linux amd64 CPU image, pinned by
digest: TorchServe **0.8.1** or **0.8.2**, Ubuntu 20.04, UID 1000 (`model-server`),
and the included JDK 17. `vendor.json` records the observed application JAR
fingerprints and Java versions. The image entrypoint and security defaults are
unchanged. The mounted configuration reduces worker/thread/queue sizes only;
no model inference workers are needed for registration and deserialization.

The native gate compiles the supplied harmless Java sources with the image's
JDK. It proves direct construction and ordinary remote `ServiceLoader` loading
before invoking the **installed** `ArchiveUtils.readYamlFile`. Plain YAML and
real MAR registration/list/unregistration provide positive controls. Every
constructor proof is read independently from disk, checked for exact content
and UID, and removed before the next producer. Downloaded MAR bytes must equal
the hosted archive. No Metasploit payload or target implementation is stubbed.

On 0.8.1, the unsafe YAML executes the constructor, then throws
`ClassCastException`; genuine MAR registration returns HTTP 500 after execution
inside TorchServe's JVM. The model never registers, DELETE returns 404 and the
downloaded MAR remains. The native fixture records that footprint and removes
its exact archive explicitly. This is fixture recovery, not proof of module
cleanup. On 0.8.2, the installed parser rejects the global tag without execution;
MAR registration nevertheless returns HTTP 200 because the application catches
the parser error. Its normal unregister removes the archive. HTTP status alone
is therefore insufficient for either verdict.

These observations agree with the [vendor 0.8.2 release](https://github.com/pytorch/serve/releases/tag/v0.8.2)
and [security advisory](https://github.com/pytorch/serve/security/advisories/GHSA-8fxr-qfr9-p34w).
Version 0.8.2 upgrades SnakeYAML and adds a warning for permissive model URLs;
the recipe does not assume that model download is prohibited.

After native calibration, the actual console module must return reason-bearing
Appears/Safe results for the two versions. The fixed profile also runs AutoCheck
twice on the same selected module, proving that its exploit body, MAR producer
and class-loader service are never entered. A passive trace records the original
requests, responses, source paths and check returns.

Each stack is capped at 1 CPU, 1536 MiB memory/equal swap and 256 PIDs; ports are
published on loopback. The runner names and labels resources and removes finished
or failed stacks immediately. Native HTTP sources also close in `finally`.
Java Meterpreter/shell owner execution, session shutdown, module artifact cleanup,
other releases and deployment configurations remain unqualified by these profiles.
Automated captures do not replace human-written module Scenarios.
