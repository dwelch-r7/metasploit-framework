# Langflow saved-flow execution target

This profile runs the official digest-pinned Langflow 1.10.0 image with
`LANGFLOW_AUTO_LOGIN=false` and `LANGFLOW_ALLOW_CUSTOM_COMPONENTS=false`.
One backend worker is used. The documented native login rate allowance is 100
per minute, with the limiter enabled. Compose caps the target at one CPU,
3 GiB, and 256 PIDs. The public-console lane uses three containers in total.

Run `bundle exec ruby tools/dev/run_guarded_module_target_tests.rb langflow_flow langflow_flow_enabled`.
The second profile enables custom components; the two profiles run serially.
The runner starts with a cold console and removes its containers, network, and
volumes when finished. Do not run this target alongside another target family.

The saved `benign_component.json` is a server-generated frontend blueprint
captured from the enabled-policy control on the same image. Its embedded Python
component returns a fixed Data object without external services. `vendor.json`
records the blueprint and installed build-route/guard source hashes. The native
probe verifies package versions, effective settings, denied direct custom
component creation, rejected typed-flow builds, and actual empty-type execution.
It deletes each canary flow and verifies the original registry afterward.

Functional acceptance requires exact command output, genuine shell and
Meterpreter session identity and file operations, reporting database origin and
closure, disappearance of the original remote process, an unchanged backend
process set, and no leftover flow, job, session, or callback connection. Each
public operation is repeated on the same selected module.

The checkpoint report records actual results and untested limits. This fixture
qualifies the owner's empty `data.type` flow-guard path on the pinned image; the
[vendor advisory](https://www.ibm.com/support/pages/node/7284733) describes a
separate template-type/ForwardRef wrapper path that this fixture does not test.
