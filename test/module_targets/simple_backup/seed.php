<?php
require '/opt/module-target/seed-base.php';
require_once ABSPATH . 'wp-admin/includes/file.php';
$files = json_decode(file_get_contents('/opt/module-target/files.json'), true);
foreach ($files as $fixture) {
    if (isset($fixture['create']) && !$fixture['create']) { continue; }
    $content = base64_decode($fixture['content_base64'], true);
    if ($content === false || file_put_contents($fixture['path'], $content) !== strlen($content)) {
        throw new RuntimeException('Owned Simple Backup fixture creation failed');
    }
    chmod($fixture['path'], 0644);
}
$version = getenv('SIMPLE_BACKUP_RELEASE') ?: '2.7.10';
if ($version !== 'absent') {
    $releases = json_decode(file_get_contents('/opt/module-target/releases.json'), true);
    if (!isset($releases[$version]) || !hash_equals($releases[$version]['sha256'], hash_file('sha256', '/opt/module-target/plugin.zip'))) {
        throw new RuntimeException('Pinned Simple Backup archive differs');
    }
    if (!WP_Filesystem()) { throw new RuntimeException('WordPress direct filesystem unavailable'); }
    $extracted = unzip_file('/opt/module-target/plugin.zip', WP_PLUGIN_DIR . '/');
    if (is_wp_error($extracted)) { throw new RuntimeException($extracted->get_error_message()); }
    $plugin = 'simple-backup/simple-backup-loader.php';
    $metadata = get_plugin_data(WP_PLUGIN_DIR . '/' . $plugin, false, false);
    if ($metadata['Version'] !== $version) { throw new RuntimeException('Installed Simple Backup version differs'); }
    $activated = activate_plugin($plugin);
    if (is_wp_error($activated)) { throw new RuntimeException($activated->get_error_message()); }
}
if (!wp_mkdir_p(ABSPATH . 'simple-backup')) { throw new RuntimeException('Local backup directory setup failed'); }
file_put_contents(ABSPATH . 'simple-backup/module-target-backup.txt', "Owned ordinary backup file\n");
file_put_contents('/tmp/module-target-simple-backup-ready', "ready\n");
