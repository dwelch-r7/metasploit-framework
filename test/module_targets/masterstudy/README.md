# MasterStudy container targets

All 38 public cases in seven serial profiles pass in one aggregate; see the
[verification report](../VERIFICATION-20261117-masterstudy.md).

```sh
bundle exec ruby test/module_targets/masterstudy/prepare.rb
bundle exec ruby tools/dev/run_guarded_module_target_tests.rb masterstudy
# All seven profiles run serially with teardown between them:
bundle exec ruby tools/dev/run_guarded_module_target_tests.rb \
  masterstudy masterstudy_fixed masterstudy_subdirectory masterstudy_plain \
  masterstudy_no_check masterstudy_custom_prefix masterstudy_empty_prefix
```

| Profile | Plugin / condition | Qualified cases |
| --- | --- | ---: |
| `masterstudy` | 2.7.5, repeats, generated/explicit values, policy/collision/route negatives | 19 |
| `masterstudy_fixed` | 2.7.6, AutoCheck block and actual partial subscriber/error | 3 |
| `masterstudy_subdirectory` | 2.7.5 under `/portal` | 3 |
| `masterstudy_plain` | 2.7.5 with verified plain permalinks | 3 |
| `masterstudy_no_check` | 2.7.5 with AutoCheck disabled | 3 |
| `masterstudy_custom_prefix` | 2.7.5, genuine `lab_` tables and a wrong-prefix subscriber control | 4 |
| `masterstudy_empty_prefix` | 2.7.5 with unprefixed tables | 3 |

The repaired default generator supplies 13 characters with lowercase, uppercase
and a digit. The real original getter could produce a value without a number;
the genuine registration endpoint rejected that exact value. Focused contracts
and a source-only public compatibility replay are retained separately. Supplied
passwords remain unchanged, including deliberately invalid values in negatives.

Database checks require exact credentials and endpoint/module identity, with a
normalized `wordpress` service and service-bound Untried login. Independently
successful WordPress authentication and capability proof are recorded separately
from that Framework status.

The owner also uses the advanced `DB_PREFIX` option, with a compatible `wp_`
default. The original hardcoded key left subscribers on a healthy `lab_` target;
changing only the owner among 111 declared inputs turns the same three cases
from two failures into a passing cohort with two administrators. A wrong supplied
prefix can still register a subscriber; tests distinguish registration success
from actual privilege. The empty-prefix profile exercises the supported string
boundary through the real console, not only through a unit contract.

The lab uses complete pinned official archives, genuine activation, public
registration nonces and WordPress authentication/capability checks. The selected
runtime is WordPress 6.8.3, PHP 8.3.28 and MariaDB 11.2.2, with an ordinary
PostgreSQL reporting role. One capped stack has at most three containers, totaling
1.75 CPUs/1,408 MiB. Mail transport is explicitly /bin/false.

Version 2.7.5 creates administrators through the capability-field request. The
same request on 2.7.6 raises a genuine vendor PHP TypeError after creating a
subscriber; its login works but user management is denied. Ordinary registration
works before and after. This is not a clean rejection or whole-product security
claim. Real frontend/admin requests initialize styles, schema/options and a
navigation post before state comparisons; these fields remain in the assertions.

Only observed owned accounts are deleted after matching ID, actual username,
email, password and session agents. The production owner retains its accounts;
operator recovery is distinct from automatic module cleanup. Historical human
Scenarios remain unchanged. CAPTCHA, email activation/premoderation, multisite,
other runtimes and other releases remain unqualified.
