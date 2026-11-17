<?php
define('WP_ADMIN', true);
$_SERVER['REQUEST_METHOD'] = 'GET';
$_SERVER['PHP_SELF'] = '/wp-admin/plugins.php';
require '/opt/module-target/seed-base.php';
require_once ABSPATH . 'wp-admin/includes/file.php';
wp_set_current_user(get_user_by('login', 'module_admin')->ID);
if (!WP_Filesystem()) { throw new RuntimeException('Native filesystem unavailable'); }
$packages = [
    ['woocommerce', '9.3.3', '/opt/module-target/woocommerce-releases.json', '/opt/module-target/woocommerce.zip'],
    ['ti-woocommerce-wishlist', getenv('TI_WISHLIST_RELEASE'), '/opt/module-target/ti-releases.json', '/opt/module-target/wishlist.zip']
];
$mode = getenv('TI_WISHLIST_MODE') ?: 'enabled';
if (!in_array($mode, ['enabled', 'inactive', 'absent', 'no_products'], true)) { throw new RuntimeException('Unknown native wishlist mode'); }
foreach ($packages as [$slug, $version, $catalogPath, $archivePath]) {
    if ($slug === 'ti-woocommerce-wishlist' && $mode === 'absent') { continue; }
    $catalog = json_decode(file_get_contents($catalogPath), true, 512, JSON_THROW_ON_ERROR);
    if (!isset($catalog[$version])) { throw new RuntimeException('Unknown native plugin release'); }
    $release = $catalog[$version];
    if (!hash_equals($release['sha256'], hash_file('sha256', $archivePath))) { throw new RuntimeException('Archive differs: ' . $slug); }
    $result = unzip_file($archivePath, WP_PLUGIN_DIR . '/');
    if (is_wp_error($result)) { throw new RuntimeException($result->get_error_message()); }
    $root = WP_PLUGIN_DIR . '/' . $slug;
    foreach ($release['installed_sha256'] as $path => $digest) {
        if (!is_file($root . '/' . $path) || !hash_equals($digest, hash_file('sha256', $root . '/' . $path))) { throw new RuntimeException('Installed source differs: ' . $slug . '/' . $path); }
    }
    chown($root, 'www-data'); chgrp($root, 'www-data');
    foreach (new RecursiveIteratorIterator(new RecursiveDirectoryIterator($root, FilesystemIterator::SKIP_DOTS), RecursiveIteratorIterator::SELF_FIRST) as $file) { chown($file->getPathname(), 'www-data'); chgrp($file->getPathname(), 'www-data'); }
}
echo "Native archives extracted and verified\n";
