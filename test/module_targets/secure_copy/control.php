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
$version = getenv('SECURE_COPY_RELEASE');
$release = json_decode(file_get_contents('/opt/module-target/releases.json'), true, 512, JSON_THROW_ON_ERROR)[$version];
$installed = is_file(WP_PLUGIN_DIR . '/secure-copy-content-protection/secure-copy-content-protection.php');
$active = is_plugin_active('secure-copy-content-protection/secure-copy-content-protection.php');
$hashes = [];
if ($installed) {
    foreach ($release['installed_sha256'] as $name => $expected) {
        $hashes[$name] = hash_file('sha256', WP_PLUGIN_DIR . '/secure-copy-content-protection/' . $name);
    }
}
$tables = [];
if ($active) {
    foreach (['ays_sccp', 'ays_sccp_block_content', 'ays_sccp_block_subscribe', 'ays_sccp_settings', 'ays_sccp_reports'] as $name) {
        $table = $wpdb->prefix . $name;
        $tables[$name] = ['columns' => $wpdb->get_results('SHOW COLUMNS FROM ' . $table, ARRAY_A), 'rows' => $wpdb->get_results('SELECT * FROM ' . $table . ' ORDER BY id', ARRAY_A)];
    }
}
echo json_encode([
    'core' => get_bloginfo('version'), 'php' => PHP_VERSION, 'uid' => posix_geteuid(),
    'installed' => $installed, 'active' => $active,
    'plugin_version' => $installed ? get_plugin_data(WP_PLUGIN_DIR . '/secure-copy-content-protection/secure-copy-content-protection.php', false, false)['Version'] : null,
    'active_plugins' => get_option('active_plugins'), 'installed_sha256' => (object)$hashes,
    'archive_sha256' => hash_file('sha256', '/opt/module-target/plugin.zip'),
    'prefix' => getenv('LAB_PREFIX') ?: '', 'permalink_structure' => get_option('permalink_structure'),
    'table_prefix' => $wpdb->prefix, 'database' => DB_NAME,
    'database_role' => $wpdb->get_var('SELECT CURRENT_USER()'), 'database_grants' => $wpdb->get_col('SHOW GRANTS'),
    'server' => $wpdb->get_var('SELECT VERSION()'), 'sql_mode' => $wpdb->get_var('SELECT @@session.sql_mode'),
    'users' => $wpdb->get_results("SELECT ID,user_login,user_pass FROM {$wpdb->users} ORDER BY ID", ARRAY_A),
    'native_tables' => (object)$tables, 'allow_url_fopen' => ini_get('allow_url_fopen'), 'registered_export' => has_action('wp_ajax_nopriv_ays_sccp_results_export_file'), 'bootstrap_output_base64' => base64_encode($output), 'db_error' => $wpdb->last_error
], JSON_PRETTY_PRINT | JSON_THROW_ON_ERROR), "\n";
