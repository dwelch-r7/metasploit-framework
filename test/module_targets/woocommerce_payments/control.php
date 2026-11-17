<?php
$_SERVER['REQUEST_METHOD'] = 'GET';
$_SERVER['HTTP_HOST'] = 'module-target.test';
$_SERVER['REQUEST_URI'] = '/';
ob_start();
require getcwd() . '/wp-load.php';
require_once ABSPATH . 'wp-admin/includes/plugin.php';
$output = ob_get_clean();
if (($argv[1] ?? '') === 'delete') {
    $name = $argv[2] ?? '';
    if (!preg_match('/^(?:native|module)_payments_[a-z0-9_]+$/', $name)) { throw new RuntimeException('Refusing non-probe cleanup'); }
    $user = get_user_by('login', $name);
    if (!$user || $user->ID <= 4) { throw new RuntimeException('Probe account not found or is baseline'); }
    require_once ABSPATH . 'wp-admin/includes/user.php';
    if (!wp_delete_user($user->ID)) { throw new RuntimeException('Native probe cleanup failed'); }
}
$release = json_decode(file_get_contents('/opt/module-target/releases.json'), true, 512, JSON_THROW_ON_ERROR)[getenv('WOO_PAYMENTS_RELEASE')];
$hashes = [];
if (is_dir(WP_PLUGIN_DIR . '/woocommerce-payments')) {
    foreach ($release['installed_sha256'] as $path => $expected) { $hashes[$path] = hash_file('sha256', WP_PLUGIN_DIR . '/woocommerce-payments/' . $path); }
}
$users = [];
foreach (get_users(['orderby' => 'ID', 'order' => 'ASC']) as $user) {
    $users[] = ['ID' => $user->ID, 'user_login' => $user->user_login, 'user_pass' => $user->user_pass, 'user_email' => $user->user_email, 'roles' => $user->roles, 'create_users' => user_can($user, 'create_users'), 'manage_options' => user_can($user, 'manage_options')];
}
$probe = null;
if (($argv[1] ?? '') === 'password') {
    $user = get_user_by('login', $argv[2]);
    $probe = $user ? ['ID' => $user->ID, 'valid' => wp_check_password($argv[3], $user->user_pass, $user->ID)] : null;
}
echo json_encode([
    'core' => get_bloginfo('version'), 'php' => PHP_VERSION, 'uid' => posix_geteuid(),
    'version' => is_file(WP_PLUGIN_DIR . '/woocommerce-payments/woocommerce-payments.php') ? get_plugin_data(WP_PLUGIN_DIR . '/woocommerce-payments/woocommerce-payments.php', false, false)['Version'] : null,
    'active_plugins' => array_values(get_option('active_plugins')), 'woocommerce_class' => class_exists('WooCommerce', false),
    'platform_filter_priority' => has_filter('determine_current_user', [\WCPay\Platform_Checkout\Platform_Checkout_Session::class, 'determine_current_user_for_platform_checkout']),
    'installed_sha256' => (object)$hashes, 'archive_sha256' => hash_file('sha256', '/opt/module-target/plugin.zip'),
    'database' => DB_NAME, 'role' => $wpdb->get_var('SELECT CURRENT_USER()'), 'grants' => $wpdb->get_col('SHOW GRANTS'), 'server' => $wpdb->get_var('SELECT VERSION()'),
    'prefix' => getenv('LAB_PREFIX') ?: '', 'mode' => getenv('WOO_PAYMENTS_MODE') ?: 'enabled', 'table_prefix' => $wpdb->prefix, 'permalink_structure' => get_option('permalink_structure'), 'config_sha256' => hash_file('sha256', ABSPATH . 'wp-config.php'),
    'users' => $users, 'usermeta' => $wpdb->get_results("SELECT user_id,meta_key,meta_value FROM {$wpdb->usermeta} ORDER BY umeta_id", ARRAY_A),
    'password_check' => $probe, 'bootstrap_output_base64' => base64_encode($output), 'db_error' => $wpdb->last_error
], JSON_PRETTY_PRINT | JSON_THROW_ON_ERROR), PHP_EOL;
