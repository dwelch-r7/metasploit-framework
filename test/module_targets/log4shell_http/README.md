# Genuine Log4j HTTP lookup target

This small JDK HTTP harness calls Apache's actual Log4j API/core libraries. It
qualifies the generic `auxiliary/scanner/http/log4shell_scanner` injection and
reporting behavior; it does not substitute for testing Struts, Solr or another
product's logging configuration.

The image compiles the included Java source and fetches the four API/core JARs
from Maven Central. `vendor.json` records their publisher SHA-1 checksums and
independently computed SHA-256 build pins. No binary is stored in the repository.
The JDK and build-stage Ruby images are pinned by digest. The target selects
Log4j 2.14.1 or 2.17.1 using an explicit classpath; metadata reports the loaded
code sources, actual versions and JAR hashes.

Profiles run **serially**, with **three containers maximum**: target (192 MiB,
0.3 CPU, 96 tasks), Framework (640 MiB, 1 CPU, 256 tasks), and temporary
PostgreSQL (128 MiB, 0.2 CPU, 64 tasks). Swap is capped at the memory allocation.
Only the HTTP port is published, on a random loopback port. Framework's LDAP
listener is internal to the temporary Compose network. The guard refuses startup
when any container already exists and removes the owned project on completion.

```sh
DOCKER_CONTEXT=default BUILDX_BUILDER=default bundle exec ruby tools/dev/run_guarded_module_target_tests.rb log4shell_2141 log4shell_2171 log4shell_disabled log4shell_jul
```

Each profile first runs `native_probe.py` independently of Framework. It verifies
loaded vendor bytes and class sources, actual Java identity, and HTTP header,
encoded path, query and unlogged controls. A loopback LDAP collector in the target
records actual BER requests. The Python client independently decodes search
requests and their empty successful responses, comparing fully expanded OS,
Java and controlled environment/property values. No Java object, serialized
payload or executable class is served; remote URL class loading is disabled.
Repeated unresolved lookups are recorded, without assuming one lookup per log.

The functional suite uses short files containing real injection points plus
blank/comment controls. It runs GET/POST, one/two headers, both obfuscated path
variants, query templates, optional sentinel leaks and an unlogged endpoint.
Every case runs twice, checks real HTTP requests and PostgreSQL vulnerability
records/references, and proves the LDAP listener, jobs and sessions are absent
after execution. Patched 2.17.1, 2.14.1 with `formatMsgNoLookups=true`, and the
standard Java logger provide separate negative profiles. Native captures,
console logs, SQL rows and cgroup failure counters remain in the runner's
private artifact directory; a green native probe alone does not qualify a module.

Sources:

- [Apache Log4j security advisories](https://logging.apache.org/security.html)
- [Log4j 2.14.1 JNDI lookup source](https://github.com/apache/logging-log4j2/blob/rel/2.14.1/log4j-core/src/main/java/org/apache/logging/log4j/core/lookup/JndiLookup.java)
- [LDAP protocol, RFC 4511](https://www.rfc-editor.org/rfc/rfc4511.html)
