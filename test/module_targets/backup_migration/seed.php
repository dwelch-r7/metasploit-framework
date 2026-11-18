<?php
define('WP_ADMIN', true);
$_SERVER['REQUEST_METHOD'] = 'GET';
$_SERVER['PHP_SELF'] = '/wp-admin/plugins.php';
require '/opt/module-target/seed-base.php';
require_once ABSPATH . 'wp-admin/includes/file.php';
wp_set_current_user(get_user_by('login', 'module_admin')->ID);
if (!WP_Filesystem() || posix_geteuid() !== 33) { throw new RuntimeException('Native filesystem actor differs'); }
$release = getenv('BACKUP_MIGRATION_RELEASE');
$catalog = json_decode(file_get_contents('/opt/module-target/releases.json'), true, 512, JSON_THROW_ON_ERROR)[$release];
if (!hash_equals($catalog['sha256'], hash_file('sha256', '/opt/module-target/plugin.zip'))) { throw new RuntimeException('Archive differs'); }
$result = unzip_file('/opt/module-target/plugin.zip', WP_PLUGIN_DIR . '/');
if (is_wp_error($result)) { throw new RuntimeException($result->get_error_message()); }
$plugin = 'backup-backup/backup-backup.php';
$result = activate_plugin($plugin);
if (is_wp_error($result) || !is_plugin_active($plugin)) { throw new RuntimeException('Native plugin activation failed'); }
foreach ($catalog['installed_sha256'] as $path => $digest) {
    $file = WP_PLUGIN_DIR . '/backup-backup/' . $path;
    if (!is_file($file) || !hash_equals($digest, hash_file('sha256', $file))) { throw new RuntimeException('Vendor file differs: ' . $path); }
}
$plugins = get_plugins();
if ($plugins[$plugin]['Version'] !== $release) { throw new RuntimeException('Installed release differs'); }
file_put_contents('/tmp/module-target-backup-migration-ready', "ready\n");
echo json_encode(['native_setup' => true, 'wordpress' => get_bloginfo('version'), 'plugin' => $plugins[$plugin]['Version'], 'php' => PHP_VERSION, 'uid' => posix_geteuid(), 'verified_vendor_files' => count($catalog['installed_sha256'])], JSON_THROW_ON_ERROR) . "\n";
