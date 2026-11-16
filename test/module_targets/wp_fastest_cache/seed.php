<?php
// Install and configure the unmodified vendor plugin through WordPress APIs.
define('WP_ADMIN', true);
$_SERVER['REQUEST_METHOD'] = 'GET';
$_SERVER['PHP_SELF'] = '/wp-admin/plugins.php';
require '/opt/module-target/seed-base.php';
require_once ABSPATH . 'wp-admin/includes/file.php';
wp_set_current_user(get_user_by('login', 'module_admin')->ID);
$mode = getenv('FASTEST_CACHE_MODE') ?: 'enabled';
if (!in_array($mode, ['enabled', 'excluded', 'disabled', 'inactive', 'absent'], true)) {
    throw new RuntimeException('Unknown native cache setting');
}
$version = getenv('FASTEST_CACHE_RELEASE');
$release = json_decode(file_get_contents('/opt/module-target/releases.json'), true)[$version];
if (!hash_equals($release['sha256'], hash_file('sha256', '/opt/module-target/plugin.zip'))) {
    throw new RuntimeException('Pinned cache archive differs');
}
if ($mode !== 'absent') {
    if (!WP_Filesystem()) { throw new RuntimeException('WordPress filesystem unavailable'); }
    $result = unzip_file('/opt/module-target/plugin.zip', WP_PLUGIN_DIR . '/');
    if (is_wp_error($result)) { throw new RuntimeException($result->get_error_message()); }
    $plugin = 'wp-fastest-cache/wpFastestCache.php';
    if (get_plugin_data(WP_PLUGIN_DIR . '/' . $plugin, false, false)['Version'] !== $version) {
        throw new RuntimeException('Cache plugin version differs');
    }
    if ($mode !== 'inactive') {
        $result = activate_plugin($plugin);
        if (is_wp_error($result)) { throw new RuntimeException($result->get_error_message()); }
        // This vendor version tests property presence, so an unchecked cache
        // setting omits the key rather than storing an 'off' value.
        $options = $mode === 'disabled' ? [] : ['wpFastestCacheStatus' => 'on'];
        // The real exclusion returns before is_user_admin for any login cookie.
        if ($mode === 'excluded') { $options['wpFastestCacheLoggedInUser'] = 'on'; }
        update_option('WpFastestCache', json_encode((object)$options));
    }
    $directory = WP_PLUGIN_DIR . '/wp-fastest-cache';
    chown($directory, 'www-data');
    chgrp($directory, 'www-data');
    $files = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($directory, FilesystemIterator::SKIP_DOTS), RecursiveIteratorIterator::SELF_FIRST);
    foreach ($files as $file) {
        chown($file->getPathname(), 'www-data');
        chgrp($file->getPathname(), 'www-data');
    }
}
if (getenv('FASTEST_CACHE_PREFIX_SCOPE') === '1') {
    // A real backup table in a second owned database cannot identify this site's
    // prefix. Copy genuine Core schema and rows; leave the connected DB intact.
    if ($wpdb->prefix !== 'wp_native_') { throw new RuntimeException('Custom prefix differs'); }
    if ($wpdb->query("CREATE TABLE wp_prefix.wp_users LIKE {$wpdb->users}") === false) {
        throw new RuntimeException($wpdb->last_error);
    }
    if ($wpdb->query("INSERT INTO wp_prefix.wp_users SELECT * FROM {$wpdb->users}") !== 4) {
        throw new RuntimeException('Native backup row copy failed');
    }
}
file_put_contents('/tmp/module-target-fastest-cache-ready', "ready\n");
