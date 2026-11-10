## Vulnerable Application

Apache ActiveMQ 5.3.1 can disclose JSP source through Jetty's catch-all resource
handler when the request starts with two slashes. The normal single-slash path
renders HTML. [AMQ-2700](https://issues.apache.org/jira/browse/AMQ-2700) identifies
5.3.2 and 5.4.0 as fixed releases. The stock 5.3.2 configuration restricts that
resource handler to `webapps/static/`.

A reusable repository lab builds genuine publisher archives on a digest-pinned
Temurin 8 runtime and independently compares raw response bytes with the actual
stock JSP files:
[test/module_targets/activemq_disclosure](../../../../../test/module_targets/activemq_disclosure/README.md).
It also checks rendered HTML, fixed/missing paths and genuine unrelated HTTP200.
Historical publisher SHA1 and detached-signature provenance, plus pinned SHA512,
are recorded alongside the shared target recipe.

`TARGETURI` is the normal path to the JSP, such as `/admin/index.jsp` or `admin/topics.jsp`. The
module adds the exploit's second slash after path normalization. Do not supply a
schemeless authority such as `//admin/index.jsp`: the shared URI parser interprets
`admin` as a host rather than as the first path component.

An HTTP200 response must contain JSP source syntax before it is stored as loot.
A rendered page, escaped example or static index alone does not establish source
exposure. Actual loot bytes are retained without rewriting.

## Verification Steps

1. From the Framework root, run
   `bundle exec ruby tools/dev/run_module_target_tests.rb activemq_disclosure`.
2. Require the independent native gate to pass before assessing module results.
3. Confirm exact source-loot hashes for `index.jsp`, `queues.jsp` and `topics.jsp`
   on both repetitions; normal rendered HTML is not source disclosure evidence.
4. Confirm fixed, missing, unrelated and non-JSP responses create no source loot.
5. Review the recorded console traces, native responses and input hashes.

## Options

No specific options

## Scenarios

No human-provided scenario transcript is included here. The repository lab
records real automated console output and source/loot evidence separately;
those records are not presented as a human scenario.
