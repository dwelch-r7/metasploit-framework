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
$version = getenv('ULTIMATE_MEMBER_RELEASE');
$release = json_decode(file_get_contents('/opt/module-target/releases.json'), true, 512, JSON_THROW_ON_ERROR)[$version];
$installed = is_file(WP_PLUGIN_DIR . '/ultimate-member/ultimate-member.php');
$active = is_plugin_active('ultimate-member/ultimate-member.php');
$hashes = [];
if ($installed) {
    foreach ($release['installed_sha256'] as $name => $expected) { $hashes[$name] = hash_file('sha256', WP_PLUGIN_DIR . '/ultimate-member/' . $name); }
}
echo json_encode([
    'core' => get_bloginfo('version'), 'php' => PHP_VERSION, 'uid' => posix_geteuid(), 'plugin_version' => $installed ? get_plugin_data(WP_PLUGIN_DIR . '/ultimate-member/ultimate-member.php', false, false)['Version'] : null, 'installed' => $installed, 'active' => $active,
    'active_plugins' => get_option('active_plugins'), 'installed_sha256' => (object)$hashes, 'archive_sha256' => hash_file('sha256', '/opt/module-target/plugin.zip'),
    'database' => DB_NAME, 'database_role' => $wpdb->get_var('SELECT CURRENT_USER()'), 'database_grants' => $wpdb->get_col('SHOW GRANTS'),
    'server' => $wpdb->get_var('SELECT VERSION()'), 'table_prefix' => $wpdb->prefix, 'prefix' => getenv('LAB_PREFIX') ?: '', 'permalink_structure' => get_option('permalink_structure'),
    'custom_meta_enabled' => $active ? UM()->options()->get('member_directory_own_table') : null, 'directory_class' => $active ? get_class(UM()->member_directory()) : null,
    'native_forms' => get_option('um_core_forms'), 'native_directories' => get_option('um_core_directories'), 'options' => get_option('um_options'),
    'forms_pages' => $wpdb->get_results("SELECT ID,post_type,post_status,post_name,post_content FROM {$wpdb->posts} WHERE post_type IN ('um_form','um_directory','page') ORDER BY ID", ARRAY_A),
    'directory_meta' => $wpdb->get_results("SELECT post_id,meta_key,meta_value FROM {$wpdb->postmeta} WHERE post_id IN (SELECT ID FROM {$wpdb->posts} WHERE post_type='um_directory') ORDER BY meta_id", ARRAY_A),
    'users' => $wpdb->get_results("SELECT ID,user_login,user_pass FROM {$wpdb->users} ORDER BY ID", ARRAY_A),
    'core_usermeta' => $wpdb->get_results("SELECT user_id,meta_key,meta_value FROM {$wpdb->usermeta} ORDER BY umeta_id", ARRAY_A),
    'custom_usermeta' => $active ? $wpdb->get_results("SELECT user_id,um_key,um_value FROM {$wpdb->prefix}um_metadata ORDER BY umeta_id", ARRAY_A) : [],
    'metadata_keys' => get_option('um_usermeta_fields'), 'bootstrap_output_base64' => base64_encode($output), 'db_error' => $wpdb->last_error
], JSON_PRETTY_PRINT | JSON_THROW_ON_ERROR), "\n";
