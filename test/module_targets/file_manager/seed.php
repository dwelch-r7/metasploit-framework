<?php
// Match the administrator activation context, without modifying vendor PHP.
define('WP_ADMIN', true);
$_SERVER['REQUEST_METHOD'] = 'GET';
$_SERVER['PHP_SELF'] = (getenv('LAB_PREFIX') ?: '') . '/wp-admin/plugins.php';
require '/opt/module-target/seed-base.php';
require_once ABSPATH . 'wp-admin/includes/file.php';
wp_set_current_user(get_user_by('login', 'module_admin')->ID);
$version = getenv('FILE_MANAGER_RELEASE') ?: '6.0';
if ($version !== 'absent') {
$release = json_decode(file_get_contents('/opt/module-target/releases.json'), true)[$version];
if (!hash_equals($release['sha256'], hash_file('sha256', '/opt/module-target/plugin.zip'))) { throw new RuntimeException('Official outer archive differs'); }
if (!WP_Filesystem()) { throw new RuntimeException('Direct WordPress filesystem unavailable'); }
if (isset($release['nested'])) {
$temporary = '/tmp/module-target-file-manager-source';
wp_mkdir_p($temporary);
$result = unzip_file('/opt/module-target/plugin.zip', $temporary);
if (is_wp_error($result)) { throw new RuntimeException($result->get_error_message()); }
$nested = $temporary . '/' . $release['nested']['member'];
if (!hash_equals($release['nested']['sha256'], hash_file('sha256', $nested))) { throw new RuntimeException('Official nested archive differs'); }
$archive = $nested;
} else { $archive = '/opt/module-target/plugin.zip'; }
$result = unzip_file($archive, WP_PLUGIN_DIR . '/');
if (is_wp_error($result)) { throw new RuntimeException($result->get_error_message()); }
$plugin = 'wp-file-manager/file_folder_manager.php';
if (get_plugin_data(WP_PLUGIN_DIR . '/' . $plugin, false, false)['Version'] !== $version) { throw new RuntimeException('Installed plugin version differs'); }
$result = activate_plugin($plugin);
if (is_wp_error($result)) { throw new RuntimeException($result->get_error_message()); }
$directory = WP_PLUGIN_DIR . '/wp-file-manager';
chown($directory, 'www-data'); chgrp($directory, 'www-data');
foreach (new RecursiveIteratorIterator(new RecursiveDirectoryIterator($directory, FilesystemIterator::SKIP_DOTS), RecursiveIteratorIterator::SELF_FIRST) as $file) { chown($file->getPathname(), 'www-data'); chgrp($file->getPathname(), 'www-data'); }
}
if (!wp_mkdir_p('/tmp/module-target-file-manager-proofs')) { throw new RuntimeException('Proof directory creation failed'); }
chown('/tmp/module-target-file-manager-proofs', 'www-data'); chgrp('/tmp/module-target-file-manager-proofs', 'www-data');
file_put_contents('/tmp/module-target-file-manager-ready', "ready\n");
