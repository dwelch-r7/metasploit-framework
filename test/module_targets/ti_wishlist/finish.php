<?php
$_SERVER['REQUEST_METHOD'] = 'GET';
$_SERVER['HTTP_HOST'] = 'module-target.test';
require getcwd() . '/wp-load.php';
require_once ABSPATH . 'wp-admin/includes/plugin.php';
$mode = getenv('TI_WISHLIST_MODE') ?: 'enabled';
if (!is_plugin_active('woocommerce/woocommerce.php')) { throw new RuntimeException('Native WooCommerce activation did not persist'); }
if (is_plugin_active('ti-woocommerce-wishlist/ti-woocommerce-wishlist.php') !== ($mode !== 'absent')) { throw new RuntimeException('Native wishlist activation did not persist'); }
if (!class_exists('WC_Product_Simple') || !did_action('woocommerce_init')) { throw new RuntimeException('Native WooCommerce initialization failed'); }
$identifier = 0;
if ($mode !== 'no_products') {
    $product = new WC_Product_Simple();
    $product->set_name('Module target native wishlist product');
    $product->set_sku('module-target-native-wishlist');
    $product->set_status('publish');
    $product->set_catalog_visibility('visible');
    $product->set_regular_price('12.50');
    $identifier = $product->save();
    if (!$identifier || !wc_get_product($identifier) || get_post_status($identifier) !== 'publish') { throw new RuntimeException('Native WooCommerce product creation failed'); }
}
if ($mode === 'inactive') { deactivate_plugins('ti-woocommerce-wishlist/ti-woocommerce-wishlist.php'); }
flush_rewrite_rules(false);
file_put_contents(getcwd() . '/.htaccess', $wp_rewrite->mod_rewrite_rules());
file_put_contents('/tmp/module-target-ti-wishlist-ready', json_encode(['product_id' => $identifier], JSON_THROW_ON_ERROR));
echo json_encode(['ready' => true, 'product_id' => $identifier, 'woocommerce' => WC()->version], JSON_THROW_ON_ERROR), PHP_EOL;
