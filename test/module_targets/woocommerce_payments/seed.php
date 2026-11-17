<?php
define('WP_ADMIN', true);
$_SERVER['REQUEST_METHOD'] = 'GET';
$_SERVER['PHP_SELF'] = '/wp-admin/plugins.php';
require '/opt/module-target/seed-base.php';
require_once ABSPATH . 'wp-admin/includes/file.php';
wp_set_current_user(get_user_by('login', 'module_admin')->ID);
if (!WP_Filesystem()) { throw new RuntimeException('Native filesystem unavailable'); }
if (getenv('WOO_PAYMENTS_MODE') === 'absent') { echo "WooPayments deliberately absent\n"; return; }
$slug = 'woocommerce-payments';
$version = getenv('WOO_PAYMENTS_RELEASE');
$release = json_decode(file_get_contents('/opt/module-target/releases.json'), true, 512, JSON_THROW_ON_ERROR)[$version];
if (!hash_equals($release['sha256'], hash_file('sha256', '/opt/module-target/plugin.zip'))) { throw new RuntimeException('Native archive differs'); }
$result = unzip_file('/opt/module-target/plugin.zip', WP_PLUGIN_DIR . '/');
if (is_wp_error($result)) { throw new RuntimeException($result->get_error_message()); }
$root = WP_PLUGIN_DIR . '/' . $slug;
foreach ($release['installed_sha256'] as $path => $digest) {
    if (!is_file($root . '/' . $path) || !hash_equals($digest, hash_file('sha256', $root . '/' . $path))) { throw new RuntimeException('Installed source differs: ' . $path); }
}
chown($root, 'www-data'); chgrp($root, 'www-data');
foreach (new RecursiveIteratorIterator(new RecursiveDirectoryIterator($root, FilesystemIterator::SKIP_DOTS), RecursiveIteratorIterator::SELF_FIRST) as $file) { chown($file->getPathname(), 'www-data'); chgrp($file->getPathname(), 'www-data'); }
echo "Native archive extracted and verified\n";
