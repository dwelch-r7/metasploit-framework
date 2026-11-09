<?php
$_SERVER['HTTP_HOST'] = 'module-target.test';
$_SERVER['REQUEST_URI'] = (getenv('LAB_PREFIX') ?: '') . '/';
require getcwd() . '/wp-load.php';
require_once ABSPATH . 'wp-admin/includes/plugin.php';
require_once ABSPATH . 'wp-admin/includes/file.php';
global $wp_version;
$accounts = [];
foreach (get_users(['orderby' => 'ID']) as $user) {
    wp_set_current_user($user->ID);
    $accounts[$user->user_login] = [
        'id' => $user->ID, 'roles' => $user->roles,
        'install_plugins' => current_user_can('install_plugins'),
        'upload_plugins' => current_user_can('upload_plugins')
    ];
}
wp_set_current_user(0);
$plugins = [];
foreach (get_plugins() as $path => $data) {
    $plugins[$path] = ['version' => $data['Version'], 'active' => is_plugin_active($path)];
}
echo json_encode([
    'version' => $wp_version, 'php' => PHP_VERSION,
    'uid' => posix_geteuid(), 'account' => posix_getpwuid(posix_geteuid())['name'],
    'install_root' => getcwd(), 'plugin_root' => WP_PLUGIN_DIR,
    'plugins_writable' => is_writable(WP_PLUGIN_DIR), 'plugins' => $plugins,
    'filesystem_method' => get_filesystem_method(), 'accounts' => $accounts,
    'file_mods_disabled' => defined('DISALLOW_FILE_MODS') && DISALLOW_FILE_MODS,
    'disabled_functions' => ini_get('disable_functions'),
    'native_command_account' => trim(shell_exec('/usr/bin/id -un'))
], JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR) . "\n";
