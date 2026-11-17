<?php
define('WP_ADMIN', true);
$_SERVER['REQUEST_METHOD'] = 'GET';
$_SERVER['HTTP_HOST'] = 'module-target.test';
$_SERVER['PHP_SELF'] = '/wp-admin/plugins.php';
require getcwd() . '/wp-load.php';
require_once ABSPATH . 'wp-admin/includes/plugin.php';
$plugin = $argv[1];
if (!in_array($plugin, ['woocommerce-payments/woocommerce-payments.php'], true)) { throw new RuntimeException('Unknown native activation'); }
wp_set_current_user(get_user_by('login', 'module_admin')->ID);
$result = activate_plugin($plugin);
if (is_wp_error($result)) { throw new RuntimeException($result->get_error_message()); }
echo json_encode(['plugin' => $plugin, 'active' => is_plugin_active($plugin)], JSON_THROW_ON_ERROR), PHP_EOL;
