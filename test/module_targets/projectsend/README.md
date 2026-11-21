# ProjectSend native-gated checks

```sh
MODULE_TARGET_NAMESPACE=my-projectsend-lab bundle exec ruby tools/dev/run_guarded_module_target_tests.rb projectsend
```

This profile uses the unchanged LinuxServer r1605-ls199 application image and a
pinned MariaDB 10.11 image. Two capped services run at a time: application 384 MiB /
0.7 CPU, database 256 MiB / 0.3 CPU, with equal memory/swap caps and temporary
configuration, uploads and database storage. Every guarded phase namespaces and
removes its containers and ephemeral network.

Native readiness writes ordinary database configuration, uses the actual HTTP
installer and fingerprints twelve application files. Stock PHP executes a self-removing
web control from the real upload directory, with exact Unicode/CRLF file proof
owned by UID 1000. Independent unauthenticated title changes through the original
options API must restore every database option. Stock PHP omits the optional
POSIX extension; the observer uses the stock id utility and physical proof UID
without installing an extension.

The fixture seeds a title containing an ampersand and Unicode, custom footer,
language/editor choices and non-default client settings. Actual repeated checks
must preserve every option. A natively refused port must return Unknown without
extra cleanup requests. Actual state is retained before deliberate fixture
recovery; restoration never converts a failed owning assertion into a pass.

Native failures withhold the module verdict. RCE, session and patched-release
paths remain pending qualification; this initial profile targets check behavior.
Ordinary unit CI excludes Docker profiles, and registration alone does not prove
this profile passes. Existing human-written console scenarios are preserved.
