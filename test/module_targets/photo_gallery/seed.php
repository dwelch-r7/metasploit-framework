<?php
define('WP_ADMIN', true); $_SERVER['REQUEST_METHOD'] = 'GET'; $_SERVER['PHP_SELF'] = '/wp-admin/plugins.php';
require '/opt/module-target/seed-base.php'; require_once ABSPATH . 'wp-admin/includes/file.php';
wp_set_current_user(get_user_by('login', 'module_admin')->ID);
$version = getenv('PHOTO_GALLERY_RELEASE');
if (getenv('PHOTO_GALLERY_MODE') === 'absent') { file_put_contents('/tmp/module-target-photo-gallery-ready', "ready\n"); return; }
$release = json_decode(file_get_contents('/opt/module-target/releases.json'), true)[$version];
if (!hash_equals($release['sha256'], hash_file('sha256', '/opt/module-target/plugin.zip'))) { throw new RuntimeException('Pinned Photo Gallery archive differs'); }
if (!WP_Filesystem()) { throw new RuntimeException('WordPress filesystem unavailable'); }
$result = unzip_file('/opt/module-target/plugin.zip', WP_PLUGIN_DIR . '/'); if (is_wp_error($result)) { throw new RuntimeException($result->get_error_message()); }
$plugin = 'photo-gallery/photo-gallery.php'; if (get_plugin_data(WP_PLUGIN_DIR . '/' . $plugin, false, false)['Version'] !== $version) { throw new RuntimeException('Photo Gallery version differs'); }
$result = activate_plugin($plugin); if (is_wp_error($result)) { throw new RuntimeException($result->get_error_message()); }
// Activation runs as the installer; HTTP activation normally owns uploads as www-data.
$uploads = wp_upload_dir(); if (!wp_mkdir_p(BWG()->upload_dir . '/thumb')) { throw new RuntimeException('Photo Gallery upload initialization failed'); }
$owned_uploads = $uploads['basedir']; chown($owned_uploads, 'www-data'); chgrp($owned_uploads, 'www-data');
foreach (new RecursiveIteratorIterator(new RecursiveDirectoryIterator($owned_uploads, FilesystemIterator::SKIP_DOTS), RecursiveIteratorIterator::SELF_FIRST) as $file) { chown($file->getPathname(), 'www-data'); chgrp($file->getPathname(), 'www-data'); }
$directory = WP_PLUGIN_DIR . '/photo-gallery'; chown($directory, 'www-data'); chgrp($directory, 'www-data');
foreach (new RecursiveIteratorIterator(new RecursiveDirectoryIterator($directory, FilesystemIterator::SKIP_DOTS), RecursiveIteratorIterator::SELF_FIRST) as $file) { chown($file->getPathname(), 'www-data'); chgrp($file->getPathname(), 'www-data'); }
file_put_contents('/tmp/module-target-photo-gallery-ready', "ready\n");
