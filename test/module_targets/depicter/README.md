# Depicter credential gathering lab

These profiles install unmodified, checksum-pinned official Depicter 3.6.1 and
3.6.2 archives into WordPress 6.8.3 / PHP 8.3.28 with MariaDB. The
[disclosure](https://www.wordfence.com/threat-intel/vulnerabilities/wordpress-plugins/depicter/slider-popup-builder-by-depicter-361-unauthenticated-sql-injection-via-s-parameter)
identifies CVE-2025-2011 and its 3.6.2 fix. The exact release sources also add
authentication and a dashboard nonce to the lead listing routes. The plugin,
its queries, HTTP responses and Framework module are real implementations.

Prepare the official archives, then run one profile from the Framework root:

```sh
export DOCKER_CONTEXT=default BUILDX_BUILDER=default
bundle exec ruby test/module_targets/depicter/prepare.rb
bundle exec ruby tools/dev/run_guarded_module_target_tests.rb depicter
```

Additional profiles are `depicter_prefix`, `depicter_table_prefix`,
`depicter_low_limit`, `depicter_fixed`, `depicter_absent` and
`depicter_unrelated`. The low-limit profile sets MariaDB's real
`group_concat_max_len` to 96 bytes. Each stack has at most three containers:
app 0.5 CPU / 384 MiB, MariaDB 0.5 CPU / 512 MiB and PostgreSQL reporting
0.5 CPU / 256 MiB. Each has 128 PIDs, an init process and equal memory/swap
limits. Published ports bind ephemeral loopback ports. Framework runs locally
with the existing bundle; the guarded launcher serializes stacks and removes
the project's containers, networks and volumes on completion or failure.

The genuine plugin creates its own schema during WordPress activation. The
lab creates a document through the plugin repository and submits a lead through
its public HTTP form endpoint using a genuine guest nonce. Before module calls,
normal searches and independent SQL extraction verify application health and
complete native user/hash values. The fixed release must support normal lead
searches after an actual administrator login and dashboard nonce, while refusing
public access and the authenticated injection. No endpoint or reply is replaced.

Functional cases compare credentials persisted in real PostgreSQL, complete
printed hashes and the exact saved loot contents against native database values.
They exercise default, limited and complete extraction, AutoCheck enabled and
disabled, repeated calls and meaningful negative targets. Before/after native
snapshots verify account hashes, lead data, plugin sources and schema preservation.
The human module guide and Scenarios remain unchanged.

Source calibration, module defects and runtime status are maintained in the
[verification record](../VERIFICATION-20261116-depicter.md). Other
plugin/core/PHP versions remain outside these profiles' scope.
