# WordPress Multicall boundary captures

`responses.json` retains selected native metadata and exact HTTP request/reply
bytes from the genuine WordPress 4.3.1/PHP 5.6.40, 4.4/PHP 5.6.40 and
6.8.3/PHP 8.3.28 lab. Its provenance records the original evidence path and
SHA-256. The independent REXML/Net::HTTP producer imports no module or login
scanner code; native PHP APIs verify account authentication and source identity.

A wrong-then-correct batch returns failure/success on 4.3.1 and failure/failure
on 4.4 and 6.8.3. Independent correct requests succeed afterward. All plugins
are inactive. Full native controls make 34 requests and distinguish a
request-scoped authentication latch from an account lockout.

The older-source entries record hashes and absence of the `auth_failed`
property in explicitly reviewed official GitHub tags. Those are source review
observations, not claims of native deployment coverage for every older release.
Version/option/state regression examples beyond the three live failures are
explicit boundary and state-preservation cases.

The build sources and native producer are in
`test/module_targets/wordpress_multicall/`. Recreate the functional profile with:

```sh
bundle exec ruby tools/dev/run_module_target_tests.rb wordpress_multicall
```
