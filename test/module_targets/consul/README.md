# Consul version discovery

```sh
bundle exec ruby tools/dev/run_module_target_tests.rb consul
```

Digest-pinned official Consul 1.20.6 and 2.0.4 agents run their real HTTP APIs
and embedded UI. Separate agents enable ACLs with a deny default and a public
fixture management token. That token is configured for internal agent operations;
it is not the default token for anonymous HTTP requests. Native Consul CLI and
Net::HTTP controls verify versions, leadership, API/UI content and successful,
incorrect and absent-token requests before Framework runs. ACL setup follows
the [vendor configuration reference](https://developer.hashicorp.com/consul/docs/reference/agent/configuration-file/acl).
The vendor documents [agent version/self API permissions](https://developer.hashicorp.com/consul/api-docs/agent)
separately; the target's actual responses establish the exercised fallback.

Eleven cases cover repeated anonymous discovery on both versions, management-token
access, absent/rejected-token API fallback, UI fallback when Consul's own
`http_config.block_endpoints` denies the two version APIs, an Apache reverse-proxy
subpath and unrelated genuine HTTP. Apache forwards actual Consul responses; no service or
response is simulated. Only random loopback HTTP ports are published, with no
host network or Docker socket. The [shared runner](../README.md) retains native
captures, console output, image identities, input hashes and owned teardown.
Registration alone is not qualification.

This profile does not qualify Consul execution modules, other releases,
enterprise builds, TLS, reverse-proxy authentication or persisted service reports.
All tokens are disposable public fixtures. Existing human Scenarios remain
unchanged.
