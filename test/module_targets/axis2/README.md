# Axis2 targets

Run from the repository root:

```sh
bundle exec ruby tools/dev/run_module_target_tests.rb axis2
```

The lab builds the original Apache Axis2 1.4.1 and 1.6.2 WAR distributions on
digest-pinned Tomcat with Java 8. Downloads must match the recorded SHA-256.
Both use the public application credentials `admin` / `axis2`.

Native HTTP probes verify the version service and both accepted and rejected
logins. The LFI test reads the actual configuration on 1.4.1 and verifies that
1.6.2 rejects the same request. Module HTTP traces must show the intended service
path, preventing an unrelated missing URL from satisfying the negative case.

The Java deployment cases require two consecutive Meterpreter and command-shell sessions per
release, using the default Spawn=2 Java profile. Rejected deployment credentials
must not upload an archive. Each session must create a previously absent proof file, and uploaded
service archives must disappear. Windows and native Linux payload delivery,
SAP BusinessObjects, TLS and restricted administration accounts remain outside
this initial profile. Results and unresolved failures are recorded in the
[campaign](../CAMPAIGN.md); the presence of a lab is not a passing result.

Only random host loopback HTTP ports are published. Framework runs on the same
Compose network; reverse listeners are not exposed on the host. See the
[shared guide](../README.md) for retained evidence and cleanup.
