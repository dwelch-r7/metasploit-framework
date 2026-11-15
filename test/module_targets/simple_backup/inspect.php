<?php
$_SERVER['HTTP_HOST'] = 'module-target.test';
$_SERVER['REQUEST_URI'] = (getenv('LAB_PREFIX') ?: '') . '/';
$_SERVER['PHP_SELF'] = (getenv('LAB_PREFIX') ?: '') . '/index.php';
$_SERVER['REQUEST_METHOD'] = 'GET';
require getcwd() . '/wp-load.php';
require_once ABSPATH . 'wp-admin/includes/plugin.php';
$plugin = 'simple-backup/simple-backup-loader.php';
$active = is_plugin_active($plugin);
$metadata = $active ? get_plugin_data(WP_PLUGIN_DIR . '/' . $plugin, false, false) : null;
$files = [];
foreach (json_decode(file_get_contents('/opt/module-target/files.json'), true) as $fixture) {
    $name = $fixture['path'];
    $exists = file_exists($name);
    $files[$name] = ['exists' => $exists, 'readable' => is_readable($name), 'size' => $exists ? filesize($name) : null, 'sha256' => $exists ? hash_file('sha256', $name) : null, 'content_base64' => $exists ? base64_encode(file_get_contents($name)) : null];
}
$backup = ABSPATH . 'simple-backup/module-target-backup.txt';
$files[$backup] = ['exists' => file_exists($backup), 'readable' => is_readable($backup), 'size' => filesize($backup), 'sha256' => hash_file('sha256', $backup), 'content_base64' => base64_encode(file_get_contents($backup))];
$slashed = add_magic_quotes(['path' => "/tmp/module-target-simple-backup-café space'file"]);
$user = get_user_by('login', 'module_admin');
$config = ABSPATH . 'wp-config.php';
$files[$config] = ['exists' => file_exists($config), 'readable' => is_readable($config), 'size' => filesize($config), 'sha256' => hash_file('sha256', $config), 'content_base64' => base64_encode(file_get_contents($config))];
$endpoint = WP_PLUGIN_DIR . '/simple-backup/simple-backup-manager.php';
echo json_encode([
    'core' => get_bloginfo('version'), 'php' => PHP_VERSION, 'sapi' => PHP_SAPI, 'uid' => posix_geteuid(),
    'prefix' => getenv('LAB_PREFIX') ?: '', 'active' => $active, 'active_plugins' => get_option('active_plugins'),
    'plugin_version' => $metadata['Version'] ?? null, 'archive_sha256' => $active ? hash_file('sha256', '/opt/module-target/plugin.zip') : null,
    'endpoint_sha256' => file_exists($endpoint) ? hash_file('sha256', $endpoint) : null,
    'user' => ['login' => $user->user_login, 'password_sha256' => hash('sha256', $user->user_pass), 'activation_key_sha256' => hash('sha256', $user->user_activation_key)],
    'files' => $files, 'config_path' => $config, 'backup_path' => $backup, 'quoted_after_magic_quotes' => $slashed['path'], 'endpoint_exists' => file_exists($endpoint)
], JSON_PRETTY_PRINT), "\n";
