# Deferred module investigations

These findings do not count as passing functional qualification. The
[campaign](CAMPAIGN.md) and individual verification records retain other
coverage limits and ongoing investigations.

## WordPress administrator upload sessions

`exploit/unix/webapp/wp_admin_shell_upload` remains unqualified. Its retained
[25-case reproducer](wordpress_admin/README.md) documents the cold-state seed
7721 and genuine WordPress/PHP native controls. Repeated staged PHP Meterpreter
execution can enter an invalid-session reconnect burst during bootstrap.
Interrupted full-profile attempts retain null counts; a bounded observer case
finishes with one failure and successful teardown. Neither is passing coverage.

Independent role/authentication, actual proof-plugin upload/execution/removal and
native PHP callback controls pass. Explicit remote exit and prior-handler
shutdown do not resolve the staged-session failure. Saved TLV observations narrow
the investigation to bootstrap/`core_loadlib` and packet transport, but lack
session/socket labels; a missing decoded reply does not establish wire silence.
The upload module has not been established as the cause, and no production
session repair is claimed.

The separately integrated upload-permission check repair passes matched ordered
20/5 to 20/0 and focused 21/9 to 21/0 comparisons. It does not qualify session
execution. Current module source SHA-256 is
`d1e640a23c27d6c2b983380b44bc4c8c493a003fefe35573994c9dad43474924`.
The [retained verification record](VERIFICATION-20261109-proxy-history.md#retained-investigation-and-remaining-work)
records independent verification of all 338 session-export and 95
permission-export checksums. Keep those failures separate from the verified
permission repair. Further work needs labeled session/socket transport evidence
through the second staged bootstrap before selecting a module or session fix.

## Ansible node deployment

`exploit/linux/local/ansible_node_deployer` remains unqualified. The native-passing
original baseline completes eight cases with six failures. Independent controls
confirm foreground node payloads blocking playbook completion, controller files
being cleaned through a node session, and selected-host calculation failures.

An isolated experimental repair improves focused tests to 23/0 and addresses
those paths. Its split functional profiles have raw 4/0 plus 4/0 counters, but
an independent audit finds a positive operator abort despite a full play recap,
actual node proof and restored files. Those counters are explicitly rejected.

A direct diagnostic returns a full recap without the success marker after
37.0165 seconds despite a sixty-second collection setting. Its independent
native exit record is absent, so its actual exit remains unknown. A final
bounded comparison obtains genuine native exit zero, node command/identity
proof and payload removal in both asynchronous and foreground modes, but both
redirect stdout. That changed collection condition does not explain the
original direct-call failure. No shared-helper repair is established.

The retained worker is
`/Users/dwelch/.codex/worktrees/ansible-deployer-validation/metasploit-framework`.
Its experimental source SHA-256 is
`1ae6f11c7e1da0c186f830cf2ca680d830679b31883b106d6531712e905872ea`;
that source is not integrated or published by this checkpoint. The durable
`ansible-deployer-diagnostic-checkpoint-20261109T221656` export retains every
baseline/diagnostic, exact source/input snapshots, native controls, proposed
patch and explicit `UNQUALIFIED.json`. The parent independently verifies all
939 checksum entries; the manifest SHA-256 is
`47f53c3e4c5a7f6d389b0f96b331c9c888fff31c3bcb04a8249c379bc7c745fc`.
The worker's final audit records all fourteen owned projects and fourteen
recorded volumes absent. No experimental source commit or PR is claimed.

Further investigation should independently capture native process completion
and exact returned bytes on an ordinary direct call before selecting a
transport or module workaround. Passing redirected commands, session counts,
recaps and focused examples alone do not qualify this deployer.
