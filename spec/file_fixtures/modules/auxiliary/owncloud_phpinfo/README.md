These are complete, unmodified HTTP response bodies from isolated ownCloud
10.12.1 vendor containers with the original Graph API 0.3.0 phpinfo test file.
They contain deliberately public lab credentials, not user credentials.

- `native-sqlite.html`: native SQLite feasibility pilot, captured on 2026-11-11
  at 21:57 UTC. Its SMTP password contains spaces, an ampersand and angle brackets.
- `native-postgres.html`: unauthenticated `GET` of
  `/apps/graphapi/vendor/microsoft/microsoft-graph/tests/GetPhpInfo.php/.css`,
  HTTP 200 at 22:26:17 UTC on 2026-11-11. The actual configured database host is
  `reporting_db:5432`; Redis is `redis` on port `6379`. The configured, disabled
  object store has a secret containing spaces and HTML entities.
- `native-prefix.html`: the same genuine vendor stack deployed under
  `/owncloud/`, captured on 2026-11-11. Its admin password is
  `module&<owncloud-password>`; the HTTP body contains the encoded entities.
- `provenance.json`: source capture paths, response hashes, native version and
  environment metadata. Dynamic hostnames, ports and process data are retained.

The native PostgreSQL/Redis preflight independently accepted the public lab
credentials and rejected incorrect passwords. Replaying these bodies in the unit
spec does not authenticate a harvested credential or prove SQL persistence.
The unit spec uses the real Framework module loader, option objects, HTTP response
HTML parser, URI builder and auxiliary failure class. HTTP transport, DNS,
loot writes and report methods are explicit doubles. DNS answers use reserved
test addresses instead of the captured container addresses.

Examples marked synthetic mutate individual captured rows or supply
nullable/error boundary values. They cover defensive behavior rather than
claiming those responses occurred in the native lab. Repeated unit executions
verify stable report arguments; database deduplication belongs to live acceptance.
SMTP retains its existing `127.0.0.1` host and port `25` defaults when those
fields are absent. Malformed captured endpoints still skip service association.

Run only this focused unit file without a test database:

```sh
SPEC_HELPER_LOAD_METASPLOIT=false bundle exec rspec spec/modules/auxiliary/gather/owncloud_phpinfo_reader_spec.rb --seed 49103
```

`OWNCLOUD_UNIT_MODULE_ROOT` may point to an independently preserved `modules/`
tree to run the identical suite against the original module source.
