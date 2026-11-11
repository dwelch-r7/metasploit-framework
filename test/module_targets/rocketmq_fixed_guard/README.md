# RocketMQ fixed-release guard

Run `bundle exec ruby tools/dev/run_guarded_module_target_tests.rb rocketmq_fixed_guard`.
This companion to the [session lab](../rocketmq_sessions/README.md) runs only the
genuine pinned 5.1.1 target and Framework: two containers, 1,408 MiB/1.25 CPUs,
256 PIDs each, one project bridge and random loopback NameServer port.

The real vendor SDK verifies identity, route, configuration and unchanged Broker
PID, attempts the native execution control over a full 36-second schedule window,
and verifies no execution and complete native restoration. Two owning exploit
calls must refuse through AutoCheck, leave no session/job/listener, and preserve
the full config, route and PID. A separate final native snapshot verifies them
again. Positive payload/session controls live in the session profile.

Splitting these roles keeps each profile within the existing ten-minute limit
without increasing resource caps or removing checks. Registration alone does not
qualify a profile; use its actual result and dated report.
