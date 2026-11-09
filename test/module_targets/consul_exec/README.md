# Consul execution investigation

```sh
bundle exec ruby tools/dev/run_module_target_tests.rb consul_exec
```

Registration alone does not establish passing module coverage. Check the
[current qualification record](../README.md) and retained result for this profile.

It reuses the pinned official Consul 1.20.6 target with explicit execution
features enabled on open/ACL-deny agents, alongside ordinary disabled defaults.
Only random loopback API ports are published. No host engine socket, network or
operator configuration is used. All tokens are public fixtures inherited from
the [version-discovery target](../consul/README.md).

Independent controls establish actual script-check registration/execution,
native `consul exec`, rejected tokens, disabled features and restored state
before testing Framework's service/rexec modules. The vendor documents the
[execution feature flags](https://developer.hashicorp.com/consul/docs/reference/agent/configuration-file/general)
and [native command/ACL contract](https://developer.hashicorp.com/consul/commands/exec).
Native success alone does not qualify Framework delivery or sessions. The
disabled native CLI returns exit zero with zero acknowledgements; file absence
and actual state, rather than that exit status, establish the negative result.

Sixteen cases cover both modules' feature checks, ACL acceptance/refusal,
repeated actual Linux x86 command payloads through printf and wget delivery,
disabled-feature execution, fresh command proof and service/check/session/KV
state restoration. Files are verified through the real container filesystem;
state is read through a separate native HTTP client. Sessions, Windows service
delivery, other releases, TLS and restricted positive ACL policies remain
unqualified. No human console Scenarios are generated.
