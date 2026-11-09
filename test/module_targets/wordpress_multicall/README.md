# WordPress Multicall credentials

From the repository root:

```sh
bundle exec ruby tools/dev/run_module_target_tests.rb wordpress_multicall
```

The family tests `auxiliary/scanner/http/wordpress_multicall_creds` with genuine
WordPress 4.3.1, 4.4 and 6.8.3. Legacy releases are built from checksum-pinned
wordpress.org archives on official digest-pinned PHP 5.6.40 Apache. The source
download stage uses current TLS support; the original Docker Hub release tags
have obsolete image manifests. MariaDB and the modern `/wordpress/` installation
reuse the [shared WordPress fixture](../wordpress/README.md). No response handlers
or authentication APIs are simulated. Legacy mail goes to `/bin/true`, updating
and cron are disabled, and native controls verify plugins remain inactive.

Reviewed [4.3.1 source](https://github.com/WordPress/WordPress/blob/4.3.1/wp-includes/class-wp-xmlrpc-server.php)
has no failed-authentication latch; the
[4.4 source](https://github.com/WordPress/WordPress/blob/4.4/wp-includes/class-wp-xmlrpc-server.php)
adds it. Archive files were checked byte-for-byte against those reviewed files.
Independent native HTTP verifies the behavioral boundary: a wrong-then-correct
two-entry batch yields failure/success on 4.3.1, but failure/failure on 4.4 and
6.8.3. A new HTTP request with correct credentials succeeds afterward. Correct
individual credentials and all-correct batches work on all three releases.
This establishes request-scoped protection rather than an account lockout.

Native PHP inspects actual versions, users, roles and source hashes. A standard
REXML/Net::HTTP client constructs scalar XML-RPC arguments independently of the
module's Nokogiri builder, captures real replies, and checks administrator,
subscriber and XML/Unicode editor credentials. Thirty-four actual requests
establish valid, incorrect and absent-account outcomes, batch behavior and
unrelated Apache identity before module assertions.

Twenty-two functional cases cover repeated credential discovery, passwords in
the first/second list positions, batch sizes observed in actual HTTP traces,
legacy/fixed/current software, root/subdirectory paths, limited users, special
passwords, incorrect/absent accounts, unrelated HTTP and invalid chunk limits.
Lists contain at most two passwords; `BLOCKEDWAIT=0` keeps unexpected HTTP
failures diagnostic instead of sleeping for six minutes. It does not simulate
rate limiting or qualify that cooldown behavior. Test passwords are generated
from the public fixture account file into the isolated artifact directory.

Only random loopback target ports are published. Source and configuration are
kept in this repository, with native responses, runtime image identities, exact
counts, source hashes and owned teardown retained by the [shared runner](../README.md).
Registration is not qualification. No human module Scenarios are generated.
Other versions, TLS, multisite, plugins/WAFs, lockout and database credential
persistence remain separate qualification work.
