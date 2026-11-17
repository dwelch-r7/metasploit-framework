<?php
$_SERVER['REQUEST_METHOD'] = 'GET';
$_SERVER['HTTP_HOST'] = 'module-target.test';
$_SERVER['REQUEST_URI'] = '/';
ob_start();
require getcwd() . '/wp-load.php';
require_once ABSPATH . 'wp-admin/includes/plugin.php';
$output = ob_get_clean();
$hashes = [];
foreach ([['woocommerce', '9.3.3', '/opt/module-target/woocommerce-releases.json'], ['ti-woocommerce-wishlist', getenv('TI_WISHLIST_RELEASE'), '/opt/module-target/ti-releases.json']] as [$slug, $version, $catalogPath]) {
    $release = json_decode(file_get_contents($catalogPath), true, 512, JSON_THROW_ON_ERROR)[$version];
    $hashes[$slug] = [];
    if (is_dir(WP_PLUGIN_DIR . '/' . $slug)) {
        foreach ($release['installed_sha256'] as $path => $expected) { $hashes[$slug][$path] = hash_file('sha256', WP_PLUGIN_DIR . '/' . $slug . '/' . $path); }
    }
    $hashes[$slug] = (object)$hashes[$slug];
}
$state = json_decode(file_get_contents('/tmp/module-target-ti-wishlist-ready'), true, 512, JSON_THROW_ON_ERROR);
$product = $state['product_id'] ? wc_get_product($state['product_id']) : false;
$tables = [];
foreach (['tinvwl_lists', 'tinvwl_items', 'tinvwl_analytics'] as $suffix) {
    $table = $wpdb->prefix . $suffix;
    if ($wpdb->get_var($wpdb->prepare('SHOW TABLES LIKE %s', $wpdb->esc_like($table))) === $table) {
        $tables[$suffix] = ['columns' => $wpdb->get_col('SHOW COLUMNS FROM ' . $table), 'rows' => $wpdb->get_results('SELECT * FROM ' . $table, ARRAY_A)];
    }
}
$wishlistFile = WP_PLUGIN_DIR . '/ti-woocommerce-wishlist/ti-woocommerce-wishlist.php';
$wishlistInstalled = is_file($wishlistFile);
$routes = rest_get_server()->get_routes();
$wishlistRoute = '/wc/v3/wishlist/(?P<share_key>[A-Fa-f0-9]{6})/get_products';
$prefixLookup = null;
if ($wpdb->prefix === 'wp_native_') {
    // Exact encoded query captured from the original failed public run.
    $query = file_get_contents('/opt/module-target/prefix-query.sql');
    $prefixLookup = [
        'value' => $wpdb->get_var($query),
        'byte5_gt127' => $wpdb->get_var('SELECT ord(mid(cast((' . $query . ') as binary),5,1))>127'),
        'byte5_gt96' => $wpdb->get_var('SELECT ord(mid(cast((' . $query . ') as binary),5,1))>96')
    ];
}
echo json_encode([
    'core' => get_bloginfo('version'), 'php' => PHP_VERSION, 'uid' => posix_geteuid(),
    'woocommerce' => WC()->version,
    'wishlist' => $wishlistInstalled ? get_plugin_data($wishlistFile, false, false)['Version'] : null,
    'wishlist_installed' => $wishlistInstalled, 'wishlist_active' => is_plugin_active('ti-woocommerce-wishlist/ti-woocommerce-wishlist.php'),
    'wishlist_route' => isset($routes[$wishlistRoute]), 'mode' => getenv('TI_WISHLIST_MODE') ?: 'enabled',
    // Deactivation may leave sparse numeric indexes. Keep the raw option as
    // evidence, and expose a stable list for membership comparisons.
    'active_plugins' => array_values(get_option('active_plugins')), 'active_plugins_option' => get_option('active_plugins'), 'installed_sha256' => $hashes,
    'product' => $product ? ['id' => $product->get_id(), 'name' => $product->get_name(), 'status' => $product->get_status(), 'type' => $product->get_type(), 'price' => $product->get_price(), 'permalink' => $product->get_permalink()] : null,
    'database' => DB_NAME, 'role' => $wpdb->get_var('SELECT CURRENT_USER()'), 'grants' => $wpdb->get_col('SHOW GRANTS'), 'server' => $wpdb->get_var('SELECT VERSION()'),
    'table_prefix' => $wpdb->prefix, 'prefix_lookup' => $prefixLookup, 'permalink_structure' => get_option('permalink_structure'),
    'prefix' => getenv('LAB_PREFIX') ?: '', 'config_sha256' => hash_file('sha256', ABSPATH . 'wp-config.php'),
    'archive_sha256' => ['woocommerce' => hash_file('sha256', '/opt/module-target/woocommerce.zip'), 'ti-woocommerce-wishlist' => hash_file('sha256', '/opt/module-target/wishlist.zip')],
    'published_product_ids' => wc_get_products(['status' => 'publish', 'limit' => -1, 'return' => 'ids']),
    'usermeta' => $wpdb->get_results("SELECT user_id,meta_key,meta_value FROM {$wpdb->usermeta} ORDER BY umeta_id", ARRAY_A),
    'users' => $wpdb->get_results("SELECT ID,user_login,user_pass FROM {$wpdb->users} ORDER BY ID", ARRAY_A),
    'native_tables' => (object)$tables, 'bootstrap_output_base64' => base64_encode($output), 'db_error' => $wpdb->last_error
], JSON_PRETTY_PRINT | JSON_THROW_ON_ERROR), PHP_EOL;
