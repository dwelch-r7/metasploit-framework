# Tomcat AJP private-file reads

Run from the repository root:

```sh
bundle exec ruby tools/dev/run_module_target_tests.rb tomcat_ghostcat
```

This family tests `auxiliary/admin/http/tomcat_ghostcat` against digest-pinned
official Tomcat 8.5.50 and 8.5.51 / OpenJDK 8 images. Apache identifies the
[8.5.51 fix boundary](https://tomcat.apache.org/security-8.html#Fixed_in_Apache_Tomcat_8.5.51).
Both expose real AJP and HTTP within the owned network, with only random
loopback host ports. The patched profile explicitly disables the newly required
AJP secret while retaining rejection of arbitrary request attributes; an
ordinary AJP request must succeed there before its refusal can be accepted.
An unrelated real Apache endpoint bounds incomplete HTTP headers to two seconds.
No target uses host data or privileged access.

Independent Python standard-library controls implement the documented
[AJP packet layout](https://tomcat.apache.org/connectors-doc/ajp/ajpv13a.html),
without importing the module or Rex parser. They verify native versions, direct
HTTP protection of `WEB-INF`, ordinary AJP access, actual private short, large,
empty, Unicode and binary file bytes, and missing-file behavior. Complete raw request
and response packets are retained. The large file spans multiple body packets;
the empty file has no body packet. The affected servlet returns HTTP 500 for a
missing included resource, while the patched connector returns 403 for these
include attributes. These are independently observed producer behaviors.

Thirteen functional cases require real check results, exact loot bytes, repeated
reads and useful refusal paths. Error pages or absent data must not be presented
as successful file loot. This family qualifies file reads in the deployed web
application, not reads outside its resource tree, JSP execution, a shell session,
other Tomcat branches, authentication, TLS or arbitrary AJP extensions. No human
module Scenarios are generated. Inspect actual assertions, exact counts, current
hashes and owned teardown using the [shared guide](../README.md); registration
alone is not passing evidence.
