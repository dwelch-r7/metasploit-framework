<?php
define('WP_ADMIN', true);
$_SERVER['HTTP_HOST'] = 'module-target.test';
$_SERVER['REQUEST_URI'] = (getenv('LAB_PREFIX') ?: '') . '/wp-admin/plugins.php';
$_SERVER['PHP_SELF'] = '/wp-admin/plugins.php';
$_SERVER['REQUEST_METHOD'] = 'GET';
ob_start();
require getcwd() . '/wp-load.php';
require_once ABSPATH . 'wp-admin/includes/plugin.php';
$output = ob_get_clean();
$version = getenv('LEARNPRESS_RELEASE');
$release = json_decode(file_get_contents('/opt/module-target/releases.json'), true)[$version];
$installed = is_file(WP_PLUGIN_DIR . '/learnpress/learnpress.php');
$hashes = [];
if ($installed) {
    foreach ($release['installed_sha256'] as $name => $expected) { $hashes[$name] = hash_file('sha256', WP_PLUGIN_DIR . '/learnpress/' . $name); }
}
echo json_encode([
    'core' => get_bloginfo('version'), 'php' => PHP_VERSION, 'uid' => posix_geteuid(),
    'installed' => $installed, 'active' => is_plugin_active('learnpress/learnpress.php'),
    'plugin_version' => $installed ? get_plugin_data(WP_PLUGIN_DIR . '/learnpress/learnpress.php', false, false)['Version'] : null,
    'active_plugins' => get_option('active_plugins'), 'installed_sha256' => (object)$hashes,
    'archive_sha256' => hash_file('sha256', '/opt/module-target/plugin.zip'),
    'tables_install_done' => class_exists('LP_Install') ? LP_Install::instance()->tables_install_done() : null,
    'prefix' => getenv('LAB_PREFIX') ?: '', 'permalink_structure' => get_option('permalink_structure'),
    'table_prefix' => $wpdb->prefix, 'database' => DB_NAME,
    'database_role' => $wpdb->get_var('SELECT CURRENT_USER()'), 'database_grants' => $wpdb->get_col('SHOW GRANTS'),
    'server' => $wpdb->get_var('SELECT VERSION()'), 'sql_mode' => $wpdb->get_var('SELECT @@session.sql_mode'),
    'backup_users' => getenv('LEARNPRESS_PREFIX_SCOPE') === '1' ? $wpdb->get_results('SELECT ID,user_login,user_pass FROM wp_prefix.wp_users ORDER BY ID', ARRAY_A) : null,
    'visible_users_tables' => $wpdb->get_results("SELECT table_schema AS db_name,table_name FROM information_schema.tables WHERE table_name LIKE '%users' ORDER BY table_schema,table_name", ARRAY_A),
    'users' => $wpdb->get_results("SELECT ID,user_login,user_pass FROM {$wpdb->users} ORDER BY ID", ARRAY_A),
    'courses' => $wpdb->get_results("SELECT ID,post_title,post_type,post_status FROM {$wpdb->posts} WHERE post_type='lp_course' ORDER BY ID", ARRAY_A),
    'plugin_tables' => $wpdb->get_col("SHOW TABLES LIKE '{$wpdb->prefix}learnpress%'") ,
    'rest_routes' => array_values(array_filter(array_keys(rest_get_server()->get_routes()), function($route) { return str_contains($route, '/courses') && (str_contains($route, 'learnpress/v1') || str_contains($route, 'lp/v1')); })),
    'bootstrap_output_base64' => base64_encode($output), 'db_error' => $wpdb->last_error
], JSON_PRETTY_PRINT), "\n";
