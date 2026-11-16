<?php
define('WP_ADMIN', true);
$_SERVER['HTTP_HOST'] = 'module-target.test';
$_SERVER['REQUEST_URI'] = (getenv('LAB_PREFIX') ?: '') . '/wp-admin/plugins.php';
$_SERVER['PHP_SELF'] = '/wp-admin/plugins.php';
$_SERVER['REQUEST_METHOD'] = 'GET';
require getcwd() . '/wp-load.php';
require_once ABSPATH . 'wp-admin/includes/plugin.php';
$mode = getenv('SECURE_COPY_MODE') ?: 'enabled';
if ($mode === 'enabled') {
    if (!is_plugin_active('secure-copy-content-protection/secure-copy-content-protection.php')) { throw new RuntimeException('Secure Copy activation did not persist'); }
    foreach (['ays_sccp', 'ays_sccp_block_content', 'ays_sccp_block_subscribe', 'ays_sccp_settings', 'ays_sccp_reports'] as $name) {
        $table = $wpdb->prefix . $name;
        if ($wpdb->get_var($wpdb->prepare('SHOW TABLES LIKE %s', $table)) !== $table) { throw new RuntimeException('Vendor installer omitted ' . $name); }
    }
    if ((int)$wpdb->get_var('SELECT COUNT(*) FROM ' . $wpdb->prefix . 'ays_sccp_block_subscribe') !== 1) { throw new RuntimeException('Native default subscription is absent'); }
    wp_set_current_user(get_user_by('login', 'module_admin')->ID);
    $post = get_page_by_path('module-target-post', OBJECT, 'post');
    $result = wp_update_post(['ID' => $post->ID, 'post_content' => '[ays_block_subscribe id="1"]MODULE_NATIVE_SUBSCRIPTION_CONTENT[/ays_block_subscribe]'], true);
    if (is_wp_error($result)) { throw new RuntimeException($result->get_error_message()); }
}
file_put_contents('/tmp/module-target-secure-copy-ready', "ready\n");
