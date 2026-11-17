# Shared WooCommerce source catalog

Pinned official WooCommerce archives support dependent WordPress target labs.
The catalog records the exact archive and every installed vendor file. Archives
stay in the ignored `tmp/module-target-woocommerce-sources` cache. Native plugin
activation, schema and product prerequisites belong to each consuming lab.

```sh
DOCKER_CONTEXT=default BUILDX_BUILDER=default bundle exec ruby test/module_targets/woocommerce/prepare.rb
```

Preparation requires an empty container inventory and the exclusive module-target
lock. Vendor code is extracted inside the owned target containers. The
[TI Wishlist target](../ti_wishlist/README.md) consumes release 9.3.3.
