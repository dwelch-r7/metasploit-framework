<?php
define('WP_ADMIN', true);
$_SERVER['REQUEST_METHOD'] = 'GET';
$_SERVER['PHP_SELF'] = '/wp-admin/plugins.php';
require '/opt/module-target/seed-base.php';
require_once ABSPATH . 'wp-admin/includes/file.php';
wp_set_current_user(get_user_by('login', 'module_admin')->ID);
$mode = getenv('LEARNPRESS_MODE') ?: 'enabled';
if (!in_array($mode, ['enabled', 'inactive', 'absent'], true)) { throw new RuntimeException('Unknown LearnPress mode'); }
$version = getenv('LEARNPRESS_RELEASE');
$release = json_decode(file_get_contents('/opt/module-target/releases.json'), true)[$version];
if (!hash_equals($release['sha256'], hash_file('sha256', '/opt/module-target/plugin.zip'))) { throw new RuntimeException('LearnPress archive differs'); }
if ($mode !== 'absent') {
    if (!WP_Filesystem()) { throw new RuntimeException('WordPress filesystem unavailable'); }
    $result = unzip_file('/opt/module-target/plugin.zip', WP_PLUGIN_DIR . '/');
    if (is_wp_error($result)) { throw new RuntimeException($result->get_error_message()); }
    $plugin = 'learnpress/learnpress.php';
    if (get_plugin_data(WP_PLUGIN_DIR . '/' . $plugin, false, false)['Version'] !== $version) { throw new RuntimeException('LearnPress version differs'); }
    if ($mode === 'enabled') {
        $result = activate_plugin($plugin);
        if (is_wp_error($result)) { throw new RuntimeException($result->get_error_message()); }
        if (!LP_Install::instance()->tables_install_done()) { throw new RuntimeException('Native LearnPress table installation incomplete'); }
    }
    $directory = WP_PLUGIN_DIR . '/learnpress';
    chown($directory, 'www-data'); chgrp($directory, 'www-data');
    foreach (new RecursiveIteratorIterator(new RecursiveDirectoryIterator($directory, FilesystemIterator::SKIP_DOTS), RecursiveIteratorIterator::SELF_FIRST) as $file) { chown($file->getPathname(), 'www-data'); chgrp($file->getPathname(), 'www-data'); }
}
