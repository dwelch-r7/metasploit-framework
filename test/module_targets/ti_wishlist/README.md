# TI WooCommerce Wishlist genuine SQLi targets

This owned lab uses official TI Wishlist 2.8.2 and fixed 2.9.0 archives,
WooCommerce 9.3.3, the pinned WordPress 6.8.3/PHP 8.3.28 image and MariaDB 11.2.2.
It reuses the [WooCommerce source catalog](../woocommerce/README.md) and
[WordPress base](../wordpress/README.md). Source hashes, native product creation,
public wishlist behavior and independent timing controls gate Framework calls.
Vendor files remain unchanged; ordinary WordPress APIs initialize the target.

```sh
DOCKER_CONTEXT=default BUILDX_BUILDER=default bundle exec ruby test/module_targets/ti_wishlist/prepare.rb
DOCKER_CONTEXT=default BUILDX_BUILDER=default bundle exec ruby tools/dev/run_guarded_module_target_tests.rb ti_wishlist
```

| Profile | Native configuration | Public cases |
| --- | --- | ---: |
| `ti_wishlist` | Affected, default COUNT=1, repeated console module, missing/reversed product range and closed port | 5 |
| `ti_wishlist_fixed` | Official 2.9.0 order allowlist | 1 |
| `ti_wishlist_prefix` | Actual `wp_native_` database tables | 1 |
| `ti_wishlist_subdirectory` | Actual `/shop` installation | 1 |
| `ti_wishlist_plain` | Native plain permalinks | 1 |
| `ti_wishlist_count2` | Two complete native user rows | 1 |
| `ti_wishlist_inactive` | Normally installed, then deactivated | 1 |
| `ti_wishlist_no_products` | Genuine empty WooCommerce product catalog | 1 |
| `ti_wishlist_absent` | Wishlist never installed; WooCommerce remains healthy | 1 |

Pass the selected profile names to the same guarded launcher to run them
serially. The module has no public `check`; these cases exercise `run`.
Time-based extraction dominates runtime. Tests use complete native hashes,
including the modern 63-byte WordPress format, and verify persisted credential,
finding and loot records. Repeated runs must keep credential IDs stable while
creating a new exact loot file. Every profile starts with a fresh reporting
database and console configuration.

The host console keeps WordPress, MariaDB and reporting PostgreSQL at three
containers. Published ports bind loopback; containers have explicit CPU, memory,
swap and PID caps. A measured 0.5-second SQL delay keeps complete native hash
checks bounded while avoiding short-delay calibration failures. Guest wishlist
records are retained until stack teardown; original users and product/source
state must remain intact. Registration and independent native proofs do not
establish accepted module coverage. See the
[campaign journal](../VERIFICATION-20261117-ti-wishlist.md) for actual results.

The [human module guide](../../../documentation/modules/auxiliary/scanner/http/wp_ti_woocommerce_wishlist_sqli.md)
retains its authored setup and Scenarios.
