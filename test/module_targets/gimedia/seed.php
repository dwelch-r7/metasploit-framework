<?php
require '/opt/module-target/seed-base.php';
require_once ABSPATH . 'wp-admin/includes/file.php';
$files = json_decode(file_get_contents('/opt/module-target/gimedia-files.json'), true);
foreach ($files as $fixture) {
    if (isset($fixture['create']) && !$fixture['create']) { continue; }
    $content = base64_decode($fixture['content_base64'], true);
    if ($content === false || file_put_contents($fixture['path'], $content) !== strlen($content)) {
        throw new RuntimeException('Owned GI-Media Library fixture creation failed');
    }
    chmod($fixture['path'], 0644);
}
$version = getenv('GIMEDIA_RELEASE') ?: '2.2.2';
if ($version !== 'absent') {
    $releases = json_decode(file_get_contents('/opt/module-target/gimedia-releases.json'), true);
    if (!isset($releases[$version]) || !hash_equals($releases[$version]['sha256'], hash_file('sha256', '/opt/module-target/plugin.zip'))) {
        throw new RuntimeException('Pinned GI-Media Library archive differs');
    }
    if (!WP_Filesystem()) { throw new RuntimeException('WordPress direct filesystem unavailable'); }
    $extracted = unzip_file('/opt/module-target/plugin.zip', WP_PLUGIN_DIR . '/');
    if (is_wp_error($extracted)) { throw new RuntimeException($extracted->get_error_message()); }
    $plugin = 'gi-media-library/gi-media-library.php';
    $metadata = get_plugin_data(WP_PLUGIN_DIR . '/' . $plugin, false, false);
    if ($metadata['Version'] !== $version) { throw new RuntimeException('Installed GI-Media Library version differs'); }
    $activated = activate_plugin($plugin);
    if (is_wp_error($activated)) { throw new RuntimeException($activated->get_error_message()); }
}
file_put_contents('/tmp/module-target-gimedia-ready', "ready\n");
