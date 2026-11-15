<?php
$_SERVER['HTTP_HOST'] = 'module-target.test';
$_SERVER['REQUEST_URI'] = (getenv('LAB_PREFIX') ?: '') . '/';
$_SERVER['PHP_SELF'] = (getenv('LAB_PREFIX') ?: '') . '/index.php';
$_SERVER['REQUEST_METHOD'] = 'GET';
require getcwd() . '/wp-load.php';
require_once ABSPATH . 'wp-admin/includes/plugin.php';
$plugin = 'bookingpress-appointment-booking/bookingpress-appointment-booking.php';
$active = is_plugin_active($plugin);
$metadata = $active ? get_plugin_data(WP_PLUGIN_DIR . '/' . $plugin, false, false) : null;
$frontend = WP_PLUGIN_DIR . '/bookingpress-appointment-booking/core/classes/frontend/class.bookingpress_appointment_bookings.php';
$page = get_page_by_path('bookingpress');
echo json_encode([
    'core' => get_bloginfo('version'), 'php' => PHP_VERSION, 'sapi' => PHP_SAPI, 'uid' => posix_geteuid(),
    'prefix' => getenv('LAB_PREFIX') ?: '', 'table_prefix' => $wpdb->prefix,
    'active' => $active, 'active_plugins' => get_option('active_plugins'),
    'plugin_version' => $active ? $metadata['Version'] : null, 'archive_sha256' => hash_file('sha256', '/opt/module-target/plugin.zip'),
    'frontend_sha256' => $active ? hash_file('sha256', $frontend) : null, 'main_sha256' => $active ? hash_file('sha256', WP_PLUGIN_DIR . '/' . $plugin) : null,
    'users' => $wpdb->get_results("SELECT ID,user_login,user_email,user_pass,user_activation_key FROM {$wpdb->users} ORDER BY ID", ARRAY_A),
    'categories' => !$active ? [] : $wpdb->get_results('SELECT * FROM ' . $wpdb->prefix . 'bookingpress_categories ORDER BY bookingpress_category_id', ARRAY_A),
    'services' => !$active ? [] : $wpdb->get_results('SELECT * FROM ' . $wpdb->prefix . 'bookingpress_services ORDER BY bookingpress_service_id', ARRAY_A),
    'page' => ['id' => $page->ID, 'content' => $page->post_content, 'status' => $page->post_status],
    'sql_mode' => $wpdb->get_var('SELECT @@sql_mode'),
    'group_concat_limit' => $wpdb->get_var('SELECT @@group_concat_max_len')
], JSON_PRETTY_PRINT), "\n";
