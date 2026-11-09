# Consul discovery and PHP wrapper investigation

The selected checkpoint covers **105 runtime modules, 45 families and 640
functional cases**. Exact counts, zero failures/pending/outside errors, current
recorded hashes and owned teardown pass for every selected family. This adds
one module and eleven cases to the
[preceding checkpoint](VERIFICATION-20261109-ansible-joomla-reporting.md).
The repository-wide campaign remains active. No PR was created or full local
RSpec suite run.

## Consul qualification

The [reusable profile](consul/README.md) runs digest-pinned official Consul
1.20.6/2.0.4 agents, separate ACL-deny agents, an agent with both version APIs
blocked through genuine Consul configuration, and actual Apache proxy/unrelated
HTTP targets. Six native CLI/config commands and 28 independent HTTP requests
verify exact versions, leadership, valid/rejected/anonymous tokens, API/UI
content and subpath forwarding. No application handler is replaced.

All eleven cases pass, including repeated anonymous discovery, management-token
access, absent/incorrect-token API fallback, exact UI discovery when the agent
blocks both APIs, a proxy subpath and unrelated HTTP refusal. No production
Consul change was needed. Final evidence:
`tmp/module-target-tests/20261109T200056-f6f283/consul`, 86.090222 seconds
including bootstrap/native controls, all 31 recorded hashes current.

The earlier `20261109T195006-612d07/consul` run missed the 120-second first
console prompt while its process remained alive. Its eleven failed setup cases
do not establish a module defect. Independent native controls had passed in a
separate owned project. Consul's selected input keys/hashes are identical in
both invocations; the independently tested PHP repair below landed between
them. The startup cause remains unclassified and no boot repair is claimed.

Audits confirm both runner projects and their ten recorded volumes absent.
The separate seven-container native project and its five recorded volumes are
also absent. New Ruby lint, the exact eleven-case dry run, module-doc tidy and
diff checks pass; existing human Scenarios are unchanged. Other releases,
enterprise builds, TLS, execution modules and persisted service reports remain
unqualified.

## Independently proven PHP repair

`Msf::Exploit::PhpEXE` emitted a fixed command-function argument while its system
block read a different generated variable. Its disabled-functions list was also
outside that function's scope. The repair uses the generated argument and
reuses the existing PHP preamble inside the command function, preserving the
outer initialization, executable bytes, destinations and unlink behavior.

The intermediate global binding failed when the wrapper was included/evaluated
inside another PHP function. Exact generated wrappers were independently run
on pinned PHP 5.6.40/8.3.28 at top level and nested include/eval, with default
and system-only command policies. The twelve-context matrix improves from six
fresh markers/six refusals to twelve clean fresh markers, without warnings or
exceptions. Focused worker regressions improve 21/2 to 21/0; the parent's
PhpEXE-only rerun passes 20/0 (thirteen owning and seven shared examples; the
worker also includes one existing EXE example). Both durable exports retain
original/intermediate evidence; all 47 and 53 checksums were parent-verified.

The parent verified the final helper digest and reviewed all 29 direct module
consumers. No previously qualified family directly includes this helper; its
repair adds no module count by itself. Windows runtime and all-consumer
qualification are not claimed. Drupal's subsequent 26-case run reached the
canonical outer limit after 25 passed cases; its timeout result remains
unqualified. A balanced nineteen/seven-case split retains the complete matrix
and is being qualified separately. Ansible deployment, JBoss and WordPress
admin investigations also remain outside these new totals.

## CI and remaining work

The aggregate selector is `tmp/module-target-checkpoint-consul-php-current.json`;
its only warning names unqualified WordPress admin. Hashes cover declared
inputs, not the entire dependency graph; other families retain selected passing
evidence rather than an all-family rerun.

At preceding published `e41ac3527a4`, Lint and six protocol suites passed in the
recorded snapshot; command-shell and Meterpreter acceptance remained queued.
[Verify](https://github.com/dwelch-r7/metasploit-framework/actions/runs/42686356575)
has one remaining existing certificate/SID OpenSSL failure, repeated on retry.
The earlier MySQL progress-state expectation no longer fails. Certificate
owning source/spec remain unchanged and causality is unclassified. New pushes
require separate inspection. Hundreds of documented container candidates and
other modules still await individual feasibility review and runtime tests.
