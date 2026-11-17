<?php
$_SERVER['REQUEST_METHOD'] = 'GET';
$_SERVER['HTTP_HOST'] = 'module-target.test';
require getcwd() . '/wp-load.php';
require_once ABSPATH . 'wp-admin/includes/plugin.php';
if (!is_plugin_active('pie-register/pie-register.php') || !class_exists('PieRegister')) { throw new RuntimeException('Native activation missing'); }
flush_rewrite_rules(false);
file_put_contents(getcwd() . '/.htaccess', $wp_rewrite->mod_rewrite_rules());
file_put_contents('/tmp/module-target-pie-ready', "ready\n");
echo json_encode(['ready'=>true],JSON_THROW_ON_ERROR), PHP_EOL;
