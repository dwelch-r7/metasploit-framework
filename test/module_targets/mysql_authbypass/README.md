# Native MySQL authentication bypass/hash collection

This opt-in lab uses Vulhub's checksum-pinned MySQL 5.5.23 build and a separate
Framework reporting database. Both containers have CPU, memory and PID caps;
ports are ephemeral loopback bindings. Use a task namespace and run serially:

```sh
MODULE_TARGET_NAMESPACE=my-mysql-tests bundle exec ruby tools/dev/run_guarded_module_target_tests.rb mysql_authbypass mysql_authbypass_open mysql_authbypass_policy mysql_authbypass_fixed
```

The upstream [source/build instructions](https://github.com/vulhub/vulhub/blob/b9999f23f7bd436f6b683a5fbd06555996848dfc/base/mysql/5.5.23/Dockerfile)
build unpatched MySQL 5.5.23 on Ubuntu Xenial. The published image digest identifies
the tested binary; rebuilding historical unpinned upstream dependencies need not
produce identical bytes. No response handler or authentication function is patched
by this lab. The root password is the public fixture `123456`.

CVE-2012-2122 depends on the build and available CPU/memcmp implementation.
The [upstream caveat](https://github.com/vulhub/vulhub/blob/b9999f23f7bd436f6b683a5fbd06555996848dfc/mysql/CVE-2012-2122/README.md)
means a version banner is insufficient. Before and after owner cases, the actual
vendor MySQL client must both reject and accept a known wrong password over TCP
as `root@%`, with a bound of 4,096 attempts. The configured root hashes are not the
wrong password's hash. A failed gate leaves the setup unqualified. The control
also verifies actual SELECT permission and denial for the two fixture users.

The owner has its own 1,000-attempt bound. Tests preserve every exhausted run and
permit at most three owner acquisitions per positive case, rechecking native
availability after exhaustion. Query, parsing or cleanup errors are never retried.
This does not guarantee a successful single operator invocation of a probabilistic
bug. Root's numeric password cannot equal the module's generated alphabetic value.

Native SQL supplies expected username/hash rows and the immutable account snapshot.
Cases retain duplicate accounts, commas, quotes, spaces and an empty hash. A real
non-administrator can read `mysql.*`; another authenticated account cannot. Tests
compare actual saved CSV rows, repeat the same console configuration and require
non-system client connections (including unauthenticated connections) to settle
back to zero without harness socket termination.
The seeded accounts live only in this disposable server. Compose teardown removes
only this newly created namespaced project; unrelated containers are preserved.

Profiles additionally cover the same unmodified server with grants disabled
(`mysql_authbypass_open`), genuine host ACL rejection (`mysql_authbypass_policy`),
and a current patched MariaDB 11.2.2 service (`mysql_authbypass_fixed`). The open
fixture seeds accounts under ordinary authentication, then restarts with the
native `--skip-grant-tables` option. It exercises immediate login, including a
nonexistent username; it is not evidence of CVE exploitation. The policy fixture
keeps only loopback grants and independently rejects its non-loopback client.
The patched fixture verifies correct-password access and 64 wrong-password
refusals before the owner exhausts its own 1,000 attempts. All modes also test an
independently closed port. Actual reporting service rows are queried in isolated
Framework workspaces. Current MariaDB negative behavior does not establish the
historical MySQL 5.5.24 fixed-version boundary.

The [verification report](../VERIFICATION-20261118-mysql-authbypass.md) records
16/0 across all four profiles, seven exact CSV files and selected server-side
connection recovery. Native setup gates remain mandatory on other hosts.
