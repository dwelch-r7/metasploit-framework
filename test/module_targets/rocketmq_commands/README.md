# RocketMQ command execution

Run `bundle exec ruby tools/dev/run_guarded_module_target_tests.rb rocketmq_commands`.
Only the genuine pinned 4.9.4 target and Framework run: two containers,
1,408 MiB memory, 1.25 CPUs, 256 PIDs per container, one isolated bridge.

The vendor SDK independently proves execution and restores its own control.
Framework then generates a real generic command with the exploit's constraints;
direct native execution must produce its fresh UID3000 marker before module calls.
Four owning calls test repeat execution with both payload-handler settings and
WfsDelay zero. Each requires a different exact marker through the real scheduled
RocketMQ process. No session count is used as command execution proof.

Without a session callback, the module cannot know when a scheduled generic
command executes. Each case records the pending configuration, then explicitly
restores the known original values through the native SDK. This operator recovery
is separate from automatic module cleanup and cannot turn a failed command into
a passing one. Full configuration, route and Broker PID must match afterward.

Registration alone is not qualification. Other releases, ACL configurations,
IPv6, binary serialization and forced execution on fixed targets are untested.
