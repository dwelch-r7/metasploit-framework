# Hadoop YARN sessions

This bounded session profile uses the genuine pinned cluster and independent
controls in [the YARN guide](../hadoop_yarn/README.md). It runs three repeated
Linux session cases separately from the sixteen check/command cases.

```sh
bundle exec ruby tools/dev/run_module_target_tests.rb hadoop_yarn yarn_live
```
