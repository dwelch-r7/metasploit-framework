# ownCloud hostname input verification — 12 November 2026

The checkpoint is **205 qualified modules, 172 profiles and 1,886 passing
functional examples**. This adds one profile/example to the
[previous checkpoint](VERIFICATION-20261111-owncloud.md). Its four profiles retain
current passing input hashes; they were not rerun for this isolated addition.
The wider campaign remains incomplete: 296 documented container hints and
unhinted candidates still need review. Registration of 207 sources is not
qualification; the three previously excluded profiles remain excluded.

## Observed behavior

The [new profile](owncloud_graph_hostname_db/README.md) supplies
`OWNCLOUD_DB_HOST=reporting_db` to the pinned genuine ownCloud 10.12.1 image with
Graph API 0.3.0. Container configuration retains that input. The running server's
environment and ownCloud configuration instead contain `reporting_db:5432`.
The vendor startup normalizes the input before the module reads phpinfo.

A native PHP process copies the running server's environment, drops to UID 33
(`www-data`) and bootstraps ownCloud. A query through its actual database
connection returns the independently observed PostgreSQL address, port 5432,
database `owncloud` and expected role. No PGPORT, PGSERVICE or PGSERVICEFILE
override is set. Before/after observations agree. The application has its own
schema, separate from Framework's reporting database.

The public module is invoked twice. Both complete HTML loot files independently
decode to the actual native environment fields. Real reporting SQL verifies
four credential cores, their services and Untried logins, including correct
secrets, resolved addresses, ports and origins. The second collection retains
the same credential IDs and creates its second loot record. Application status,
accepted/rejected authentication controls, app files and process identity are
preserved. These are lab credentials; SMTP and disabled S3 settings remain
disclosure fixtures without external authentication.

## Evidence and classification

Final source: `6520f08078c17f8e5e8d6d5217e6f967bb7d3868`.
Run: `20261112T000605-378cd3`. Manager and live observer both exit zero.
One functional example passes in 87.44 spec seconds, with no pending or
outside-example errors. Cold console prompt/BOOT and two fresh metadata
snapshots are observed without a seeded first cache. All 53 selected inputs
match current source; the production module is unchanged from the previous
checkpoint.

Two original runs remain separately sealed and are **fixture failures**:

- `20261111T235428-31d116`: a plain CLI exec misses vendor-exported defaults,
  including the database table prefix. The application probe fails before any
  module call. Native HTTP/authentication controls still pass.
- `20261112T000206-f4ed28`: the corrected process connects successfully, but the
  probe incorrectly expects the unnormalized hostname. It stops before module
  invocation. This establishes no module defect.

The final read-only evidence package `owncloud-hostname-verified-20261112` has
120 entries; its manifest SHA256 is
`0fe50b754db177c0c5176068de688ae98e2e8efde2690e20e55663467643c9bf`.
Raw records remain under `tmp/module-target-tests/20261112T000605-378cd3/`.
Python syntax, changed-spec RuboCop and whitespace checks pass. No shared runner,
common lab helper, module source or human-written Scenarios changed.

**Summary:** The genuine vendor normalization case passes; it does not reproduce
a captured database hostname without a port.

**What looks good:** Independent native connection proof agrees with complete
loot, actual persisted records, repeats and cleanup.

**Concerns:** A truly hostname-only captured endpoint remains synthetic-only.
Provider defaults, MySQL sockets and libpq overrides need a separate genuine
reproduction before changing association behavior. Other versions, TLS and
MySQL/SQLite module execution remain unqualified.

**Suggestions:** Continue with the next feasible target family. Keep runtime
work serial and distinguish fixture assumptions from demonstrated module bugs.

The project uses four containers capped at 1,504 MiB/1.65 CPUs. All ten
independent exact-resource/project/global cleanup queries pass on the same
Docker engine/context, including an empty global container list. No unrelated
containers were removed in these three runs because none were present.

```sh
bundle exec ruby tools/dev/run_guarded_module_target_tests.rb owncloud_graph_hostname_db
```

Publication is to the user's fork branch; no PR is created. CI is assessed
separately from local functional qualification.
