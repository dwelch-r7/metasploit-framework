<?php
$_SERVER['REQUEST_METHOD'] = 'GET';
$_SERVER['HTTP_HOST'] = 'module-target.test';
require getcwd() . '/wp-load.php';
require_once ABSPATH . 'wp-admin/includes/plugin.php';
if (!is_plugin_active('pie-register/pie-register.php') || !class_exists('PieRegister') || !defined('OPTION_PIE_REGISTER')) { throw new RuntimeException('Native plugin activation did not persist'); }
$options = get_option(OPTION_PIE_REGISTER);
if (!is_array($options)) { throw new RuntimeException('Native plugin settings were not installed'); }
echo json_encode(['configured'=>true,'options'=>array_intersect_key($options,array_flip(['alternate_login','alternate_register','block_WP_login','login_after_register','captcha_in_login_value']))],JSON_THROW_ON_ERROR), PHP_EOL;
