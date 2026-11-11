# Genuine JMX and registry owning profile

```sh
nice -n 10 bundle exec ruby tools/dev/run_guarded_module_target_tests.rb java_jmx
```

Four containers are capped at 1,536 MiB/1.3 CPUs. Three ordinary Temurin 17
JVMs provide anonymous JMX, password-protected JMX and an empty registry plus
an additional registry with two dynamic-proxy aliases. The Framework uses the
internal network. Host ports are random loopback bindings.

Readable Java sources and a pinned compiler image are shared with
[the Java component](../java_rmi/README.md). The native `jmx` mode requires real
SDK list/lookup/remote methods, actual MBean attributes, anonymous and bad-password
refusals, valid authenticated access and fresh server-PID marker execution through
the standard MLet loader. MBeans and files are removed and checked before/after.

Nine owning cases retain repeats, empty-registry/HTTP negatives, returned endpoint
checks and call-through reporting/wire observations. DGC positive classification
has its separate preserved deferred profile; this profile does not qualify the
Java RMI class-loading scanner. Configuration is not evidence of passing tests.
SQL persistence and other JVM versions remain separate.
