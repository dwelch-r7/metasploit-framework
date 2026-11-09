# Drupal and JBoss management qualification

The selected checkpoint covers **110 runtime modules, 48 families and 690
functional cases**. Every selected result has its exact count, zero
failures/pending/outside errors, matching current recorded hashes and owned
teardown. Relative to the [preceding checkpoint](VERIFICATION-20261109-consul-php.md),
this adds five modules, three profiles and fifty cases. The campaign remains
active. No PR was created or full local RSpec suite run.

| Profile | Qualified behavior | Cases / seconds |
|---|---|---:|
| [Drupal 7](drupal7/README.md) | Real affected/fixed installs, checks, repeated commands and Linux executable sessions | 19 / 274.236548 |
| [Drupal PHP](drupal7_php/README.md) | Memory/dropper, automatic/explicit/fallback and staged PHP sessions | 7 / 344.544904 |
| [JBoss management](jboss/README.md) | Real status/policy scans and repeated exact WAR deployment/execution/removal | 24 / 440.019489 |

Durations include each profile's bootstrap and independent controls. Reusable
Compose files live with their family guides; module docs link to them. Images
and upstream archives are pinned, published ports are random loopback ports,
and callbacks remain on owned networks. Human Scenarios are unchanged.

## Drupal evidence

Official Drupal 7.57/7.58 archives run genuine standard-profile installs on
PHP 5.6.40 and MariaDB. Separate databases cover root, subpath, fixed release,
assert-disabled and missing-changelog installations; unrelated Apache is a
negative. Each profile passes 88 native HTTP requests, thirty marker attempts
and three real callbacks. Native code/runtime/database identity and refused
administrator routes establish the fixture before module assertions.

The original 26-case run produced thirteen reported failures after an uncaught
console timeout desynchronized later output; those are diagnostic labels, not
thirteen independent module defects. The corrected full matrix reached the
600-second outer bound after 25 cases passed. Both runs remain unqualified.
The nineteen/seven split preserves all 26 case descriptions and twice-per-case
proofs, without increasing the suite limit or sharing session state. Twenty
final session executions prove fresh www-data-owned commands and cleanup. No
payload-file recovery was needed. Only source metadata is reused between the
two fresh consoles/configurations.

Final evidence: `tmp/module-target-tests/20261109T200341-6e90aa/`, with all
56/59 respective input hashes current. One Drupal runtime module is counted
once across both profiles. Production Drupal source is unchanged; the separately
proven PhpEXE repair is described in the preceding report. PHP 5.6's assert
callback rejects Drupal's second argument, so these applications exercise the
existing CLI fallback. Drupal 8, the in-process assert path, other architectures,
TLS and gated/contributed routes remain unqualified.

## JBoss evidence and repairs

Publisher-verified JBoss AS 4.2.3.GA runs on pinned Temurin 8u412/Linux amd64.
Open, legacy GET/POST-only constraints and all-method HTTP authentication are
real vendor configurations. Native CLI/HTTP controls establish version, actual
management/listener policies, valid/rejected credentials, deployment MBeans,
exact WAR bytes, JSP execution and restored files/live registrations.

The original run was **24/5**. Three failed examples reflected two incorrect
harness expectations: missing local WARs must fail OptPath before execution,
and repository HEAD cleanup can physically complete before JBoss returns 500.
Strict file/registry restoration remains required; no error guard was weakened.
Two genuine defects were repaired separately:

- Accepted credentials crashed the scanner on `workspace.id` without a database.
  Reusing `myworkspace_id` preserves connected reporting fields and standalone
  scan completion. Focused captures improve 10/1 to 10/0.
- BSH HEAD created a stager before a vendor response-wrapper failure returned 500,
  then stopped before final WAR upload. Optional confirmation now observes the
  freshly generated stager independently. Captured original JSP bytes and two
  native cycles prove parameterless GET does not create the WAR, then require
  POST upload, exact bytes, execution and cleanup. Unconfirmed 500 stays false;
  package guessing stops after an indeterminate side effect. Nil/blank stager
  requests are refused. Default no-block helper behavior is preserved.

The repaired **24/0** run is `20261109T200748-1931f3/jboss`, with all 47 inputs
current, 85 native commands/812 HTTP observations and no operator fallback
cleanup. HTTP counts include bounded deployer polling. Original evidence has
70 commands/588 observations. Final focused checks pass 75/0, including nineteen
new owning, 49 existing JBoss and seven shared examples; the parent independently
reran the same 75. Original 45 input keys expand by two captured-stager files;
six common keys change. This is not claimed as an identical-input comparison.

Known limits remain explicit: the scanner does not confirm the native-proven
HEAD 500 bypass, and HEAD removal can print an unable-to-remove error despite
actual restoration. Passing target-state assertions do not qualify that
detection path or resolve the indeterminate operator output. Other AS/EAP/JDK
versions, Windows/native payloads, TLS, serialized invokers, Seam and connected
database reporting remain separate work. HTTP-secured targets retain vendor
RMI/JNP inside the disposable network. JBoss payload sessions are excluded here.

## Independent integration and continuing queue

The parent verified all 104 Drupal and 64 JBoss imported regular files, including
dotfiles, byte for byte; raw worker revisions/paths/commands remain original.
All 452 Drupal and 338 JBoss durable-export checksums pass. Passing Drupal projects
and both recorded volumes are absent; both JBoss management projects are absent
and recorded no anonymous mounts. New Ruby lint and diff checks pass; existing
module/helper/doc diagnostics retain their inherited signatures.

Selector: `tmp/module-target-checkpoint-drupal-jboss-current.json`. Only Consul
execution and WordPress admin lack current passing results in this checkout.
Hashes describe selected inputs, not a complete dependency graph. Prior
families retain current selected evidence, rather than an all-family rerun.
Ansible deployment and JBoss session qualification are in separate worktrees.
The slow Ansible command boundary has native before/after collection evidence;
its final eight-case run is still underway. The first Consul execution run
stopped in native PID selection before any module ran and is being retried.

At published `5696755d1d8`, Lint, LDAP, SMB and MySQL CI passed in the recorded
snapshot; remaining jobs were queued/in progress. Preceding Verify retained an
existing certificate/SID OpenSSL failure with unchanged owning source/spec and
unclassified causality. New pushes need separate inspection; overall green CI
is not claimed. Hundreds of documented container candidates and other modules
still await individual feasibility review and functional tests.
