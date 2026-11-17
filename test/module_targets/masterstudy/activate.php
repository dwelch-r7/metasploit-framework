<?php
define('WP_ADMIN', true);
$_SERVER['REQUEST_METHOD'] = 'GET';
$_SERVER['HTTP_HOST'] = 'module-target.test';
$_SERVER['PHP_SELF'] = '/wp-admin/plugins.php';
require getcwd().'/wp-load.php';
require_once ABSPATH.'wp-admin/includes/plugin.php';
wp_set_current_user(get_user_by('login', 'module_admin')->ID);
$plugin = 'masterstudy-lms-learning-management-system/masterstudy-lms-learning-management-system.php';
$result = activate_plugin($plugin);
if (is_wp_error($result) || !is_plugin_active($plugin)) { throw new RuntimeException(is_wp_error($result) ? $result->get_error_message() : 'Activation failed'); }
echo "Native activation passed\n";
