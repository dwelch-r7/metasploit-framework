# SSH credential collection profile

```sh
bundle exec ruby tools/dev/run_module_target_tests.rb credential_files_ssh
```

This six-case profile selects SSH collection from the shared credential spec.
It reuses the genuine targets and independent authentication/permission
controls, with fresh database and console state. See the
[credential file guide](../credential_files/README.md) for setup, exact scope,
client provenance, no-data controls and limitations.
