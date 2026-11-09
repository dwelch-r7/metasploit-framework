# Ghostcat native AJP responses

`responses.json` retains genuine response packet bytes from digest-pinned
official Tomcat 8.5.50 and 8.5.51 / OpenJDK 8 containers. The source run, exact
native evidence digest and producer identities are recorded in its provenance.
The independent Python standard-library client implements the published AJP
layout and reads each complete response through END_RESPONSE; it imports
neither this module nor Rex's AJP parser.

Expected file bytes come from native `cat`, not from decoding the same packet
stream under test. The lab creates deterministic short, 54,272-byte, empty,
Unicode, binary and web.xml fixtures. Packet bytes are base64 for lossless
storage, including NUL and 0xff bytes. The source/build instructions live in
`test/module_targets/tomcat_ghostcat/`; recreate with:

```sh
bundle exec ruby tools/dev/run_module_target_tests.rb tomcat_ghostcat
```

The affected server returns 500 for a missing included resource; the fixed
connector returns 403 for include attributes while ordinary AJP GET works.
Derived regression cases explicitly truncate or alter captured packet bytes;
they are robustness boundaries, not claims of additional observed live faults.
