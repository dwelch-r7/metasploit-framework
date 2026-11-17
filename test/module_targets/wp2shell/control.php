<?php
$_SERVER['HTTP_HOST'] = 'module-target.test';
$_SERVER['REQUEST_URI'] = (getenv('LAB_PREFIX') ?: '') . '/';
$_SERVER['REQUEST_METHOD'] = 'GET';
ob_start();
require getcwd() . '/wp-load.php';
require_once ABSPATH . 'wp-admin/includes/plugin.php';
$output = ob_get_clean();
$catalog = json_decode(file_get_contents('/opt/module-target/releases.json'), true, 512, JSON_THROW_ON_ERROR);
$release = $catalog[getenv('WORDPRESS_CORE_RELEASE')];
$hashes = [];
foreach ($release['installed_sha256'] as $path => $digest) { $hashes[$path] = is_file(ABSPATH . $path) ? hash_file('sha256', ABSPATH . $path) : null; }
echo json_encode([
    'core' => get_bloginfo('version'), 'php' => PHP_VERSION, 'uid' => posix_geteuid(), 'installed_sha256' => $hashes,
    'archive_sha256' => hash_file('sha256', '/opt/module-target/core.tar.gz'), 'config_sha256' => hash_file('sha256', ABSPATH . 'wp-config.php'),
    'database' => DB_NAME, 'database_role' => $wpdb->get_var('SELECT CURRENT_USER()'), 'database_grants' => $wpdb->get_col('SHOW GRANTS'), 'server' => $wpdb->get_var('SELECT VERSION()'),
    'table_prefix' => $wpdb->prefix, 'prefix' => getenv('LAB_PREFIX') ?: '', 'active_plugins' => get_option('active_plugins'),
    'options' => ['home' => get_option('home'), 'siteurl' => get_option('siteurl'), 'permalink_structure' => get_option('permalink_structure')],
    'external_object_cache' => wp_using_ext_object_cache(), 'object_cache_dropin' => is_file(WP_CONTENT_DIR . '/object-cache.php'),
    'users' => $wpdb->get_results("SELECT ID,user_login,user_pass FROM {$wpdb->users} ORDER BY ID", ARRAY_A),
    'usermeta' => $wpdb->get_results("SELECT user_id,meta_key,meta_value FROM {$wpdb->usermeta} ORDER BY umeta_id", ARRAY_A),
    'posts' => $wpdb->get_results("SELECT * FROM {$wpdb->posts} ORDER BY ID", ARRAY_A),
    'postmeta' => $wpdb->get_results("SELECT post_id,meta_key,meta_value FROM {$wpdb->postmeta} ORDER BY meta_id", ARRAY_A),
    'post_columns' => $wpdb->get_col("SHOW COLUMNS FROM {$wpdb->posts}"),
    'db_error' => $wpdb->last_error, 'bootstrap_output_base64' => base64_encode($output)
], JSON_PRETTY_PRINT | JSON_THROW_ON_ERROR), "\n";
