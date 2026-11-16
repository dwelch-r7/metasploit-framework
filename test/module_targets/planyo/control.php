<?php
$_SERVER['HTTP_HOST'] = 'module-target.test'; $_SERVER['REQUEST_URI'] = (getenv('LAB_PREFIX') ?: '') . '/'; $_SERVER['REQUEST_METHOD'] = 'GET';
require getcwd() . '/wp-load.php'; require_once ABSPATH . 'wp-admin/includes/plugin.php';
$version = getenv('PLANYO_RELEASE'); $catalog = json_decode(file_get_contents('/opt/module-target/releases.json'), true)[$version];
$installed = file_exists(WP_PLUGIN_DIR . '/planyo-online-reservation-system/planyo.php'); $hashes = [];
foreach (($installed ? $catalog['installed_sha256'] : []) as $name => $expected) { $hashes[$name] = hash_file('sha256', WP_PLUGIN_DIR . '/planyo-online-reservation-system/' . $name); }
$files = [];
foreach (json_decode(file_get_contents('/opt/module-target/files.json'), true) as $name => $fixture) {
    $path = $fixture['path']; $exists = file_exists($path); $readable = $exists && is_readable($path);
    $files[$name] = ['path' => $path, 'exists' => $exists, 'readable' => $readable, 'size' => $exists ? filesize($path) : null, 'mode' => $exists ? decoct(fileperms($path) & 0777) : null, 'owner_uid' => $exists ? fileowner($path) : null, 'sha256' => $readable ? hash_file('sha256', $path) : null, 'base64' => $readable ? base64_encode(file_get_contents($path)) : null];
}
echo json_encode(['core' => get_bloginfo('version'), 'php' => PHP_VERSION, 'uid' => posix_geteuid(), 'prefix' => getenv('LAB_PREFIX') ?: '', 'installed' => $installed, 'active' => is_plugin_active('planyo-online-reservation-system/planyo.php'), 'active_plugins' => get_option('active_plugins'), 'plugin_version' => $installed ? get_plugin_data(WP_PLUGIN_DIR . '/planyo-online-reservation-system/planyo.php', false, false)['Version'] : null, 'archive_sha256' => hash_file('sha256', '/opt/module-target/plugin.zip'), 'installed_sha256' => (object)$hashes, 'files' => $files, 'users' => $wpdb->get_results("SELECT ID,user_login,user_pass FROM {$wpdb->users} ORDER BY ID", ARRAY_A), 'db_error' => $wpdb->last_error], JSON_PRETTY_PRINT), "\n";
