# WordPress XML-RPC captures

`responses.json` retains actual HTTP replies from the digest-pinned official
WordPress 6.8.3 / PHP 8.3.28 Apache container in the module-target WordPress lab.
Fixture accounts, passwords and `example.test` addresses are public test data.

The native control run `20261109T160148-15bea4` verified the genuine core version,
installed accounts/roles and correct/incorrect authentication through PHP APIs.
Its independent HTTP requests produced the GET 405 POST-only identity,
administrator user list, subscriber/editor permission fault 401, incorrect or
missing account fault 403, blocked endpoint and unrelated Apache page. The JSON
records the complete source native artifact SHA-256.

`unescaped_request` is a further actual native reply from the isolated worker
run `20261109T160531-6adaf9`: the original library's generated request for
`module_editor` / `module-target-&<café>` returns XML-RPC parse fault -32700.
The correctly escaped UTF-8 native request for the same identity returns the
permission-only fault 401. This distinguishes request corruption from a bad
password or target setup error.

The regression spec explicitly derives additional status-code, whitespace,
truncation, numeric identifier and unrelated-content boundaries from these captures. Those derived
cases do not claim additional live software/version qualification.
