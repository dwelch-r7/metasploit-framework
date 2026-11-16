<?php
define('WP_ADMIN', true);
$_SERVER['REQUEST_METHOD'] = 'GET';
$_SERVER['PHP_SELF'] = '/wp-admin/plugins.php';
require '/opt/module-target/seed-base.php';
require_once ABSPATH . 'wp-admin/includes/file.php';
wp_set_current_user(get_user_by('login', 'module_admin')->ID);
$version = getenv('CP_CALENDAR_RELEASE');
$catalog = json_decode(file_get_contents('/opt/module-target/releases.json'), true, 512, JSON_THROW_ON_ERROR);
if (!isset($catalog[$version])) { throw new RuntimeException('Unknown Calendar release'); }
$release = $catalog[$version];
if (!hash_equals($release['sha256'], hash_file('sha256', '/opt/module-target/plugin.zip'))) { throw new RuntimeException('Calendar archive differs'); }
if (!WP_Filesystem()) { throw new RuntimeException('WordPress filesystem unavailable'); }
$mode = getenv('CP_CALENDAR_MODE') ?: 'enabled';
if (!in_array($mode, ['enabled', 'inactive', 'absent'], true)) { throw new RuntimeException('Unknown Calendar mode'); }
if ($mode !== 'absent') {
    $result = unzip_file('/opt/module-target/plugin.zip', WP_PLUGIN_DIR . '/');
    if (is_wp_error($result)) { throw new RuntimeException($result->get_error_message()); }
    $directory = WP_PLUGIN_DIR . '/cp-multi-view-calendar';
    if ($release['archive_root'] !== 'cp-multi-view-calendar') {
        // The pinned SVN mirror export has a commit-named wrapper directory.
        // Install the original plugin tree at its normal basename, without edits.
        if (!rename(WP_PLUGIN_DIR . '/' . $release['archive_root'], $directory)) { throw new RuntimeException('Calendar archive root could not be installed'); }
    }
    foreach ($release['installed_sha256'] as $name => $expected) {
        if (!hash_equals($expected, hash_file('sha256', $directory . '/' . $name))) { throw new RuntimeException('Installed Calendar source differs: ' . $name); }
    }
    $plugin = 'cp-multi-view-calendar/cp-multi-view-calendar.php';
    if (get_plugin_data(WP_PLUGIN_DIR . '/' . $plugin, false, false)['Version'] !== $version) { throw new RuntimeException('Calendar version differs'); }
    if ($mode === 'enabled') {
        // The vendor supports normal bulk activation without its publish-wizard redirect.
        $_SERVER['REQUEST_METHOD'] = 'POST';
        $_POST['action'] = 'activate-selected';
        $result = activate_plugin($plugin);
        if (is_wp_error($result)) { throw new RuntimeException($result->get_error_message()); }
        foreach (['dc_mv_calendars', 'dc_mv_configuration', 'dc_mv_events', 'dc_mv_views'] as $name) {
            $table = $wpdb->prefix . $name;
            if ($wpdb->get_var($wpdb->prepare('SHOW TABLES LIKE %s', $table)) !== $table) { throw new RuntimeException('Native Calendar installer omitted: ' . $name); }
        }
        if ((int)$wpdb->get_var('SELECT COUNT(*) FROM ' . $wpdb->prefix . 'dc_mv_calendars') < 1) { throw new RuntimeException('Native installer omitted its default calendar'); }
    }
    chown($directory, 'www-data'); chgrp($directory, 'www-data');
    foreach (new RecursiveIteratorIterator(new RecursiveDirectoryIterator($directory, FilesystemIterator::SKIP_DOTS), RecursiveIteratorIterator::SELF_FIRST) as $file) { chown($file->getPathname(), 'www-data'); chgrp($file->getPathname(), 'www-data'); }
}
file_put_contents('/tmp/module-target-cp-calendar-ready', "ready\n");
