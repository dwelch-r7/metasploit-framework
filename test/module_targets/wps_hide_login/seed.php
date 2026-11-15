<?php
require '/opt/module-target/seed-base.php';
require_once ABSPATH . 'wp-admin/includes/file.php';

$releases = json_decode(file_get_contents('/opt/module-target/wps-releases.json'), true, 512, JSON_THROW_ON_ERROR);
$key = getenv('WPS_HIDE_RELEASE') ?: 'affected';
if ($key === 'absent') {
    file_put_contents('/tmp/module-target-wps-source.json', 'null');
    file_put_contents('/tmp/module-target-wps-ready', "ready\n");
    return;
}
if (!isset($releases[$key])) {
    throw new RuntimeException('Unknown pinned WPS Hide Login release');
}
$release = $releases[$key];
$slug = getenv('WPS_HIDE_SLUG');
if ($slug === false || $slug === '') { $slug = 'module-login-alpha'; }
if ($slug !== sanitize_title($slug) || $slug === '') {
    throw new RuntimeException('WPS Hide Login fixture slug is not canonical');
}
$transfer = curl_init($release['url']);
curl_setopt_array($transfer, [
    CURLOPT_RETURNTRANSFER => true, CURLOPT_FAILONERROR => true,
    CURLOPT_FOLLOWLOCATION => true, CURLOPT_MAXREDIRS => 3,
    CURLOPT_CONNECTTIMEOUT => 10, CURLOPT_TIMEOUT => 60
]);
$archive = curl_exec($transfer);
$error = curl_error($transfer);
curl_close($transfer);
if (!is_string($archive) || !hash_equals($release['sha256'], hash('sha256', $archive))) {
    throw new RuntimeException('Pinned WPS Hide Login download or checksum failed: ' . $error);
}
$path = tempnam(sys_get_temp_dir(), 'module-target-wps-');
if ($path === false) {
    throw new RuntimeException('Could not allocate the owned plugin archive');
}
try {
    if (file_put_contents($path, $archive) !== strlen($archive)) {
        throw new RuntimeException('Could not save the verified plugin archive');
    }
    if (!WP_Filesystem()) {
        throw new RuntimeException('WordPress direct filesystem initialization failed');
    }
    $extracted = unzip_file($path, WP_PLUGIN_DIR . '/');
    if (is_wp_error($extracted)) {
        throw new RuntimeException('WordPress plugin extraction failed: ' . $extracted->get_error_message());
    }
    $plugin = 'wps-hide-login/wps-hide-login.php';
    $metadata = get_plugin_data(WP_PLUGIN_DIR . '/' . $plugin, false, false);
    if ($metadata['Version'] !== $release['version']) {
        throw new RuntimeException('Installed plugin release differs from the verified archive');
    }
    $activated = activate_plugin($plugin);
    if (is_wp_error($activated)) {
        throw new RuntimeException('WordPress plugin activation failed: ' . $activated->get_error_message());
    }
    update_option('whl_page', $slug);
    flush_rewrite_rules(true);
    if (!is_plugin_active($plugin) || get_option('whl_page') !== $slug) {
        throw new RuntimeException('Real plugin activation or stored login slug differs');
    }
    file_put_contents('/tmp/module-target-wps-source.json', json_encode($release, JSON_PRETTY_PRINT | JSON_THROW_ON_ERROR));
    file_put_contents('/tmp/module-target-wps-ready', "ready\n");
} finally {
    unlink($path);
}
