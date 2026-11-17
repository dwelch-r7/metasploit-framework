<?php
define('WP_ADMIN', true);
$_SERVER['REQUEST_METHOD'] = 'GET';
$_SERVER['HTTP_HOST'] = 'module-target.test';
$_SERVER['SERVER_SOFTWARE'] = 'Apache';
$_SERVER['PHP_SELF'] = '/wp-admin/plugins.php';
require getcwd().'/wp-load.php';
require_once ABSPATH.'wp-admin/includes/plugin.php';
wp_set_current_user(get_user_by('login','module_admin')->ID);
$result = activate_plugin('hash-form/hash-form.php');
if (is_wp_error($result) || !is_plugin_active('hash-form/hash-form.php')) { throw new RuntimeException(is_wp_error($result)?$result->get_error_message():'Native activation failed'); }
echo json_encode(['active'=>true,'version'=>defined('HASHFORM_VERSION')?HASHFORM_VERSION:null],JSON_THROW_ON_ERROR),PHP_EOL;
