<?php
$_SERVER['HTTP_HOST'] = 'module-target.test';
$_SERVER['REQUEST_URI'] = (getenv('LAB_PREFIX') ?: '') . '/';
require getcwd() . '/wp-load.php';
require_once ABSPATH . 'wp-admin/includes/plugin.php';
require_once ABSPATH . 'wp-admin/includes/file.php';
wp_set_current_user(get_user_by('login', 'module_admin')->ID);
$deleted = delete_plugins(['module-target-native/module-target-native.php']);
if (is_wp_error($deleted) || !$deleted || is_dir(WP_PLUGIN_DIR . '/module-target-native')) {
    throw new RuntimeException('Native control plugin was not removed');
}
if (file_exists('/tmp/module-target-native-upload-proof')) {
    unlink('/tmp/module-target-native-upload-proof');
}
echo "Native control cleanup completed\n";
