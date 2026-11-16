<?php
// CLI inspection bypasses the frontend output buffer, not the HTTP exploit path.
define('WP_ADMIN', true);
$_SERVER['HTTP_HOST'] = 'module-target.test';
$_SERVER['REQUEST_URI'] = (getenv('LAB_PREFIX') ?: '') . '/wp-admin/plugins.php';
$_SERVER['PHP_SELF'] = '/wp-admin/plugins.php';
$_SERVER['REQUEST_METHOD'] = 'GET';
ob_start();
require getcwd() . '/wp-load.php';
require_once ABSPATH . 'wp-admin/includes/plugin.php';
$bootstrap_output = ob_get_clean();
$version = getenv('FASTEST_CACHE_RELEASE');
$release = json_decode(file_get_contents('/opt/module-target/releases.json'), true)[$version];
$plugin = WP_PLUGIN_DIR . '/wp-fastest-cache/wpFastestCache.php';
$installed = is_file($plugin);
$hashes = [];
if ($installed) {
    foreach ($release['installed_sha256'] as $name => $expected) {
        $hashes[$name] = hash_file('sha256', WP_PLUGIN_DIR . '/wp-fastest-cache/' . $name);
    }
}
$options = get_option('WpFastestCache', '');
echo json_encode([
    'core' => get_bloginfo('version'), 'php' => PHP_VERSION, 'uid' => posix_geteuid(),
    'prefix' => getenv('LAB_PREFIX') ?: '', 'active' => is_plugin_active('wp-fastest-cache/wpFastestCache.php'),
    'installed' => $installed, 'active_plugins' => get_option('active_plugins'),
    'plugin_version' => $installed ? get_plugin_data($plugin, false, false)['Version'] : null,
    'archive_sha256' => hash_file('sha256', '/opt/module-target/plugin.zip'), 'installed_sha256' => (object)$hashes,
    'cache_options' => $options ? json_decode($options) : null, 'table_prefix' => $wpdb->prefix,
    'database' => DB_NAME, 'database_role' => $wpdb->get_var('SELECT CURRENT_USER()'),
    'database_grants' => $wpdb->get_col('SHOW GRANTS'), 'server' => $wpdb->get_var('SELECT VERSION()'),
    'sql_mode' => $wpdb->get_var('SELECT @@session.sql_mode'),
    'group_concat_max_len' => $wpdb->get_var('SELECT @@session.group_concat_max_len'),
    'visible_users_tables' => $wpdb->get_results("SELECT table_schema AS db_name,table_name FROM information_schema.tables WHERE table_name LIKE '%users' ORDER BY table_schema,table_name", ARRAY_A),
    'backup_users' => getenv('FASTEST_CACHE_PREFIX_SCOPE') === '1' ? $wpdb->get_results('SELECT ID,user_login,user_pass FROM wp_prefix.wp_users ORDER BY ID', ARRAY_A) : null,
    'users' => $wpdb->get_results("SELECT ID,user_login,user_pass FROM {$wpdb->users} ORDER BY ID", ARRAY_A),
    'levels' => $wpdb->get_results("SELECT user_id,meta_key,meta_value FROM {$wpdb->usermeta} WHERE meta_key LIKE '%user_level' ORDER BY user_id", ARRAY_A),
    'bootstrap_output_base64' => base64_encode($bootstrap_output), 'db_error' => $wpdb->last_error
], JSON_PRETTY_PRINT), "\n";
