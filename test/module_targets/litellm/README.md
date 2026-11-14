# LiteLLM native SQLi targets

Qualification results and limitations are recorded in the [verification report](../VERIFICATION-20261114-litellm.md).

These profiles use the genuine pinned LiteLLM images and their vendor PostgreSQL migrations. A separate, non-superuser application role cannot connect to the Framework reporting database. All three services use an internal network; HTTP probes execute inside it. No external model or provider account is needed for the authentication-error path.

The target uses a 2 GiB cap; a 1 GiB feasibility attempt was OOM-killed before API readiness. The observed peak during the original module run was about 1.33 GiB. Only one profile runs at a time. The guarded runner records process exits, resource limits and cleanup.

```sh
DOCKER_CONTEXT=default BUILDX_BUILDER=default bundle exec ruby tools/dev/run_guarded_module_target_tests.rb litellm litellm_fixed litellm_mitigated
```

The empty virtual-key table is an explicit detection limit. Native controls provision real API-generated keys and compare true/false delay predicates before module execution. Successful time probes create ordinary unauthorized-request spend/error audit entries and daily aggregates; tests preserve all other application records and do not delete those audit records.
