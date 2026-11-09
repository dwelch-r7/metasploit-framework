# WordPress core discovery and login

From the repository root:

```sh
bundle exec ruby tools/dev/run_module_target_tests.rb wordpress
```

The family exercises `auxiliary/scanner/http/wordpress_scanner`,
`auxiliary/scanner/http/wordpress_login_enum` and
`auxiliary/scanner/http/wordpress_xmlrpc_login` through their real console entry
points. The Compose lab uses digest-pinned official WordPress 6.8.3 / PHP 8.3
Apache and MariaDB 11.2.2 images. These are disposable local test deployments;
the selected release does not imply a current security recommendation.

Four independent databases back a root installation, a `/wordpress/`
installation, a root installation with plain permalinks, and a root installation
whose Apache configuration denies XML-RPC. The latter retains bundled Akismet's
readme protection. The other three explicitly permit only its `readme.txt`,
exercising metadata disclosure as well as protected metadata. The genuine
bundled plugins remain inactive. A separate genuine Apache target is unrelated.
Only random loopback HTTP ports are published. There is no host database mount,
mail delivery, cron, automatic updating or external WordPress HTTP access.

Native PHP APIs install and inspect the actual software, users, roles, plugins,
themes and published post. Independent HTTP controls verify exact version files,
the native REST author route, valid and invalid HTML logins, authenticated
profile identity, author archives, XML-RPC availability and actual `wp.getUsers`
results. Administrator credentials return users; valid subscriber/editor
credentials return a permission fault, while incorrect credentials return a
distinct authentication fault. The special editor password includes XML
metacharacters and Unicode. Native responses and command statuses are retained
even when preflight fails; a running container alone never establishes readiness.

The 39 functional cases use two plugin names and four theme names, never the
full brute-force lists. They cover root/subdirectory paths, pretty/plain REST
routing, protected and accessible metadata, absent components, version-only and
empty-list selection, published-author discovery and exact username loot,
existing/absent username validation, repeated valid logins, special, wrong and
blank passwords, XML-RPC permission distinctions, blocked endpoints and
unrelated HTTP. This family asserts authentication and discovery, not a shell
session. It does not claim database credential persistence without an active
Framework database. No human module Scenarios are generated.

Fixture credentials are public and disposable:

| Account | Role | Password |
| --- | --- | --- |
| module_admin | administrator | module-target-password |
| module_author | author, one published post | module-target-author-password |
| module_subscriber | subscriber, no posts | module-target-subscriber-password |
| module_editor | editor, no posts | `module-target-&<café>` |

Inspect exact counts, native preflight, source hashes and teardown in each run's
artifacts using the [shared guide](../README.md). Different WordPress/PHP
releases, multisite, localized login messages, TLS, reverse proxies, plugin
authentication and database persistence require separate qualification.
