# Genuine H2 console lab

This target runs the unmodified H2 1.4.199, 2.0.204 or 2.1.214 Maven JAR with
its real JDBC engine and two real web consoles. `vendor.json` records exact
artifact sizes, SHA-256 and publisher SHA-1 checksums; the build verifies the
SHA-256 and size before installing each JAR. The Java 8 JDK base is digest-pinned.
`Bootstrap.java` only seeds a canary table and restricted account and starts
vendor servers; it does not emulate responses or execute module payloads.

The default profile uses 2.1.214; `h2_console_204` and `h2_console_199` reuse the
same image and select the other versions. The console on 8082 permits new
databases. The console on 8083 requires an existing database. Both have the
existing `jdbc:h2:./state/known` database with administrator `sa` /
`module-target-admin` and restricted `reader` / `module-target-reader`.
These are disposable lab credentials. Remote alias creation requires database
administrator rights. This is a feature-abuse test, so none of these versions
is labelled a fixed version.

From the Framework repository root:

```sh
DOCKER_CONTEXT=default BUILDX_BUILDER=default bundle exec ruby tools/dev/run_guarded_module_target_tests.rb h2_console h2_console_204 h2_console_199
```

The guarded runner owns one fresh project at a time, checks resource bounds,
uses a read-only Framework checkout and disposable console configuration, saves
receipts under `tmp/module-target-tests/`, and removes its containers and network
in an ensure block. Each profile uses three containers: target (320 MiB, 0.5 CPU),
Framework (768 MiB, 1 CPU) and reporting database (128 MiB, 0.2 CPU). Published
ports bind to localhost. No named volume is created. Do not run the services
manually against a network containing other machines.

`native_probe.py` verifies real JDBC version/canary data, independently executes
and removes an administrator alias, confirms the reader's actual permission
denial, and exercises valid/invalid credentials and both database-creation
policies through HTTP. All native commands and HTTP responses are saved. Native
controls run before and after the owning module. Successful native JDBC logins
between independent wrong-password cases reset H2's default authentication
backoff; its security delay remains enabled. The functional spec exercises
public console check/run commands, exact foreground commands, Bash shells and
the default Python Meterpreter, with repeated execution and observed cleanup.
`process_state.py` independently records real process births and callback sockets.

The supported matrix is Linux/amd64, Java 8, the three listed H2 versions and
these explicit policies. It does not establish all H2 release/JDK combinations,
HTTPS, proxies, Windows, external JDBC backends or every command payload.
See the [verification checkpoint](../VERIFICATION-20261114-h2.md) for actual
results and any unresolved failures.
