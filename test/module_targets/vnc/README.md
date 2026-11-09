# Native VNC authentication targets

```sh
bundle exec ruby tools/dev/run_module_target_tests.rb vnc
```

This profile runs the distribution's actual x11vnc0.9.16 against an actual Xvfb
320x240 framebuffer. The Ubuntu22.04 base is digest-pinned and direct package
versions are pinned in the Dockerfile. Six servers provide None or DES
challenge-response security over actual RFB3.3,3.7,3.8 handshakes. A seventh
service is unrelated HTTP. No desktop input, external displays or host X socket
are used. Passwords are public test credentials; services have random loopback
publications and owned Compose networks, following the [shared guide](../README.md).

The independent Python client follows [RFC6143](https://datatracker.ietf.org/doc/html/rfc6143),
uses the target's installed DES implementation and reads real ServerInit data.
Native controls prove offered security, acceptance of the known password and its
longer eight-byte equivalent, rejection of an incorrect password, and the actual
framebuffer size/name. This does not depend on Framework's handshake or cipher.

Twenty cases exercise both modules across all three protocol versions: repeated
None detection, protected-service negatives, correct/longer/incorrect/blank
passwords, explicit rejection of unsupported None by the password scanner, and
unrelated-service negatives. Cases use single candidates or the explicit two
known equivalent passwords, with no dictionary sweep. Successful scan output
proves authentication; desktop interaction is outside these modules' purpose.

Apple ARD, RFB4.001, VeNCrypt/TLS, vendor-specific servers, view-only sessions,
desktop control and credential database persistence remain unqualified. See the
[campaign](../CAMPAIGN.md) for actual results and findings.
