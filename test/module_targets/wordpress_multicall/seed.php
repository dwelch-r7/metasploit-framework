<?php
define('WP_INSTALLING', true);
$_SERVER['HTTP_HOST'] = 'module-target.test';
$_SERVER['REQUEST_URI'] = '/';
require getcwd() . '/wp-load.php';
require_once ABSPATH . 'wp-admin/includes/upgrade.php';
$accounts = json_decode(file_get_contents('/opt/module-target/accounts.json'), true);
if (!is_blog_installed()) {
    $installed = wp_install('Module target WordPress Multicall', 'module_admin', 'module-admin@example.test', true, '', $accounts['module_admin']['password']);
    if (is_wp_error($installed)) {
        throw new RuntimeException($installed->get_error_message());
    }
}
require '/opt/module-target/prep.php';
file_put_contents('/tmp/module-target-ready', "ready\n");
