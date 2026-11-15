<?php
$_SERVER['HTTP_HOST'] = 'module-target.test';
$_SERVER['REQUEST_URI'] = (getenv('LAB_PREFIX') ?: '') . '/';
$_SERVER['PHP_SELF'] = (getenv('LAB_PREFIX') ?: '') . '/index.php';
$_SERVER['REQUEST_METHOD'] = 'GET';
require getcwd() . '/wp-load.php';
require_once ABSPATH . 'wp-admin/includes/plugin.php';
$plugin = 'dukapress/dukapress.php';
$active = is_plugin_active($plugin);
$metadata = $active ? get_plugin_data(WP_PLUGIN_DIR . '/' . $plugin, false, false) : null;
$files = [];
foreach (json_decode(file_get_contents('/opt/module-target/dukapress-files.json'), true) as $fixture) {
    $name = $fixture['path'];
    $exists = file_exists($name);
    $files[$name] = ['exists' => $exists, 'readable' => is_readable($name), 'size' => $exists ? filesize($name) : null, 'sha256' => $exists ? hash_file('sha256', $name) : null, 'content_base64' => $exists ? base64_encode(file_get_contents($name)) : null];
}
$user = get_user_by('login', 'module_admin');
$fixture_definitions = json_decode(file_get_contents('/opt/module-target/dukapress-files.json'), true);
$quoted_path = $fixture_definitions['quoted']['path'];
$slashed = add_magic_quotes(['src' => $quoted_path]);
echo json_encode([
    'core' => get_bloginfo('version'), 'php' => PHP_VERSION, 'sapi' => PHP_SAPI, 'uid' => posix_geteuid(),
    'prefix' => getenv('LAB_PREFIX') ?: '', 'active' => $active, 'active_plugins' => get_option('active_plugins'),
    'plugin_version' => $metadata['Version'] ?? null, 'archive_sha256' => $active ? hash_file('sha256', '/opt/module-target/plugin.zip') : null,
    'endpoint_sha256' => $active ? hash_file('sha256', WP_PLUGIN_DIR . '/dukapress/lib/dp_image.php') : null,
    'resize_source_sha256' => $active ? hash_file('sha256', WP_PLUGIN_DIR . '/dukapress/php/dp-functions.php') : null,
    'user' => ['login' => $user->user_login, 'password_sha256' => hash('sha256', $user->user_pass), 'activation_key_sha256' => hash('sha256', $user->user_activation_key)],
    'files' => $files, 'quoted_path_after_core_magic_quotes' => $slashed['src']
], JSON_PRETTY_PRINT), "\n";
