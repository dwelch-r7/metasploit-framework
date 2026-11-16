<?php
define('WP_ADMIN', true);
$_SERVER['REQUEST_METHOD'] = 'GET';
$_SERVER['PHP_SELF'] = '/wp-admin/plugins.php';
require '/opt/module-target/seed-base.php';
require_once ABSPATH . 'wp-admin/includes/file.php';
wp_set_current_user(get_user_by('login', 'module_admin')->ID);
$version = getenv('SECURE_COPY_RELEASE');
$catalog = json_decode(file_get_contents('/opt/module-target/releases.json'), true, 512, JSON_THROW_ON_ERROR);
if (!isset($catalog[$version])) { throw new RuntimeException('Unknown Secure Copy release'); }
$release = $catalog[$version];
if (!hash_equals($release['sha256'], hash_file('sha256', '/opt/module-target/plugin.zip'))) { throw new RuntimeException('Secure Copy archive differs'); }
if (!WP_Filesystem()) { throw new RuntimeException('WordPress filesystem unavailable'); }
$mode = getenv('SECURE_COPY_MODE') ?: 'enabled';
if (!in_array($mode, ['enabled', 'inactive', 'absent'], true)) { throw new RuntimeException('Unknown Secure Copy mode'); }
if ($mode !== 'absent') {
    $result = unzip_file('/opt/module-target/plugin.zip', WP_PLUGIN_DIR . '/');
    if (is_wp_error($result)) { throw new RuntimeException($result->get_error_message()); }
    $directory = WP_PLUGIN_DIR . '/secure-copy-content-protection';
    foreach ($release['installed_sha256'] as $name => $expected) {
        if (!is_file($directory . '/' . $name) || !hash_equals($expected, hash_file('sha256', $directory . '/' . $name))) { throw new RuntimeException('Installed Secure Copy source differs: ' . $name); }
    }
    chown($directory, 'www-data'); chgrp($directory, 'www-data');
    foreach (new RecursiveIteratorIterator(new RecursiveDirectoryIterator($directory, FilesystemIterator::SKIP_DOTS), RecursiveIteratorIterator::SELF_FIRST) as $file) { chown($file->getPathname(), 'www-data'); chgrp($file->getPathname(), 'www-data'); }
    if ($mode === 'enabled') {
        // Normal activation persists state before the vendor's final redirect exits.
        // A second process verifies that state and finishes the fixture.
        $result = activate_plugin('secure-copy-content-protection/secure-copy-content-protection.php');
        if (is_wp_error($result)) { throw new RuntimeException($result->get_error_message()); }
    }
}
