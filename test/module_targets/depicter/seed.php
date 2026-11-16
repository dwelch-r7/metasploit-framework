<?php
// Use genuine WordPress administrator activation without changing vendor PHP.
define('WP_ADMIN', true);
$_SERVER['REQUEST_METHOD'] = 'GET';
$_SERVER['PHP_SELF'] = '/wp-admin/plugins.php';
require '/opt/module-target/seed-base.php';
require_once ABSPATH . 'wp-admin/includes/file.php';
wp_set_current_user(get_user_by('login', 'module_admin')->ID);
$version = getenv('DEPICTER_RELEASE');
if (getenv('DEPICTER_MODE') === 'absent') { file_put_contents('/tmp/module-target-depicter-ready', "ready\n"); return; }
$release = json_decode(file_get_contents('/opt/module-target/releases.json'), true)[$version];
if (!hash_equals($release['sha256'], hash_file('sha256', '/opt/module-target/plugin.zip'))) { throw new RuntimeException('Pinned Depicter archive differs'); }
if (!WP_Filesystem()) { throw new RuntimeException('WordPress direct filesystem unavailable'); }
$result = unzip_file('/opt/module-target/plugin.zip', WP_PLUGIN_DIR . '/');
if (is_wp_error($result)) { throw new RuntimeException($result->get_error_message()); }
$plugin = 'depicter/depicter.php';
if (get_plugin_data(WP_PLUGIN_DIR . '/' . $plugin, false, false)['Version'] !== $version) { throw new RuntimeException('Installed Depicter version differs'); }
$result = activate_plugin($plugin);
if (is_wp_error($result)) { throw new RuntimeException($result->get_error_message()); }
$directory = WP_PLUGIN_DIR . '/depicter';
chown($directory, 'www-data'); chgrp($directory, 'www-data');
foreach (new RecursiveIteratorIterator(new RecursiveDirectoryIterator($directory, FilesystemIterator::SKIP_DOTS), RecursiveIteratorIterator::SELF_FIRST) as $file) { chown($file->getPathname(), 'www-data'); chgrp($file->getPathname(), 'www-data'); }
file_put_contents('/tmp/module-target-depicter-ready', "ready\n");
