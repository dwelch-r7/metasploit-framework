# Consul service and rexec execution qualification

The selected checkpoint covers **112 runtime modules, 49 families and 706
functional cases**, with exact counts, zero failures/pending/outside errors,
matching current recorded hashes and owned teardown for every selected profile.
This adds two modules and sixteen cases to the
[preceding checkpoint](VERIFICATION-20261109-drupal-jboss.md). The broader goal
remains active. No PR was created or full local RSpec suite run.

## Meaningful execution and controls

The [reusable lab](consul_exec/README.md) extends official digest-pinned Consul
1.20.6 targets with explicitly enabled execution, ordinary disabled defaults
and real ACL-deny policy. The tested environment is Linux amd64 with Linux x86
command payloads; other CPU/runtime environments are not qualified.

Sixteen cases exercise `exploit/multi/misc/consul_service_exec` and
`exploit/multi/misc/consul_rexec_exec`: enabled/disabled checks, accepted/rejected
ACL tokens, repeated actual command execution through printf/wget stagers,
disabled-feature execution and denied execution. Fresh files must have the
native daemon's actual UID. Independent native HTTP snapshots require original
service/check/session/KV identifiers, and native filesystem reads require no
unexpected temporary paths after operator proof-file removal. Every positive
execution repeats with fresh proof. Reverse-shell/Meterpreter payloads and
Windows delivery are not claimed by these command-payload cases.

The final preflight records 33 native commands and 21 HTTP requests, including
real script-check registration/execution/removal, native `consul exec`, denied
service/session operations and accepted/refused credentials. Counts include
bounded polling and are not unique coverage counts. The disabled native CLI
returns exit zero with zero acknowledgements; absence of command proof and
actual state establish the negative, not its exit status. No application or API
handler is replaced. Ports bind randomly to loopback, with no host socket or
host network.

## Failure classification and focused repair

The first canonical run, `20261109T202508-3b49a7/consul_exec`, stopped before
module execution: `pidof consul` included a concurrent health-check CLI. Its
sixteen setup failures do not establish a module defect. Native process
selection now identifies the unique agent command before inspecting its UID.

The baseline with passing native controls, `20261109T203121-a378a9/consul_exec`, completes
**16/1** in 178.839182 seconds. The rejected-token rexec path raises
`NoMethodError` after session creation is refused. A separate native control
created/destroyed a session with the valid fixture token, received actual
HTTP 403 for the same request with the incorrect token, and verified unchanged
session state. Both real responses are retained as unit fixtures.

The owning repair rejects missing, denied, unexpected-status and unusable-ID
creation replies before attempting a command job. HTTP 401/403 becomes
`Failure::NoAccess` with the operation, ACL_TOKEN and session permission context;
no reply becomes Unreachable, while bad status/document shapes become
UnexpectedReply. It reuses the existing response JSON helper and preserves
successful session data. Nine owning regressions fail before and pass after;
the full focused file improves **16/9 to 16/0**, including seven shared examples.
Uncaptured status/body boundaries are explicitly synthetic unit inputs.

Final evidence is `tmp/module-target-tests/20261109T204401-053cda/consul_exec`:
**16/0**, 184.596466 seconds, zero pending/outside errors, all 33 recorded hashes
current and cleanup passed. Relative to the baseline with passing native controls, no input
keys are added/removed and only the owning module and native probe change; the
probe additionally verifies the actual denied session-creation operation. Every
functional assertion remains unchanged. Exact original 33-file snapshots are
preserved for both earlier runs, without rewriting raw provenance.

## Integration, retention and limits

All three runner projects and nine recorded volumes audit absent. The separate
three-agent native project/three volumes and single-agent API control project/
one volume also audit absent. The durable export
`consul-execution-20261109-223a7ad38fd` contains 273 checksummed files, including
raw runs, exact original input snapshots, native controls, unit/lint evidence and
both commits. Every checksum was independently reread and verified.

New Ruby files lint clean. The owning module's 45 inherited diagnostics decrease
to 44 with none added; module tidy retains its legacy/no-CVE informational
notices. No new human console Scenarios were invented. Restricted positive ACL
policies, other releases, TLS, alternate agent users/architectures and reverse
payloads remain unqualified. Failures after later rexec stages require separate
investigation; the repair is scoped to creation.

The existing check methods label enabled feature flags Vulnerable without an
active command probe. These cases record that current output; independent
native execution establishes the fixture's behavior separately. Aligning check
confidence with the passive evidence remains a deferred finding for both modules.

Aggregate selector: `tmp/module-target-checkpoint-consul-execution-current.json`.
Its sole warning names the unqualified WordPress admin reproducer. Recorded
hashes cover selected inputs, not the whole dependency graph; prior families
retain current selected evidence rather than rerunning every family. Ansible
deployment, JBoss payload sessions and Linux credential-file collection continue
separately. Latest pushed CI must be inspected independently; preceding snapshots
retain the existing certificate/SID OpenSSL failure and no overall green-CI claim.
