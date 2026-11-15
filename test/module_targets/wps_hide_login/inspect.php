<?php
$_SERVER['HTTP_HOST'] = 'module-target.test';
$_SERVER['REQUEST_URI'] = (getenv('LAB_PREFIX') ?: '') . '/';
$_SERVER['PHP_SELF'] = (getenv('LAB_PREFIX') ?: '') . '/index.php';
$_SERVER['REQUEST_METHOD'] = 'GET';
require getcwd() . '/wp-load.php';
require_once ABSPATH . 'wp-admin/includes/plugin.php';
$plugin = 'wps-hide-login/wps-hide-login.php';
$metadata = is_file(WP_PLUGIN_DIR . '/' . $plugin) ? get_plugin_data(WP_PLUGIN_DIR . '/' . $plugin, false, false) : null;
echo json_encode([
    'core' => get_bloginfo('version'), 'php' => PHP_VERSION, 'sapi' => PHP_SAPI,
    'uid' => posix_geteuid(), 'active' => is_plugin_active($plugin),
    'plugin_version' => $metadata ? $metadata['Version'] : null,
    'configured_slug' => get_option('whl_page', null), 'prefix' => getenv('LAB_PREFIX') ?: '',
    'home' => get_option('home'), 'siteurl' => get_option('siteurl'),
    'active_plugins' => get_option('active_plugins'),
    'plugin_sha256' => $metadata ? hash_file('sha256', WP_PLUGIN_DIR . '/' . $plugin) : null,
    'readme_sha256' => is_file(WP_PLUGIN_DIR . '/wps-hide-login/readme.txt') ? hash_file('sha256', WP_PLUGIN_DIR . '/wps-hide-login/readme.txt') : null,
    'verified_release' => json_decode(file_get_contents('/tmp/module-target-wps-source.json'), true, 512, JSON_THROW_ON_ERROR)
], JSON_PRETTY_PRINT | JSON_THROW_ON_ERROR), "\n";
