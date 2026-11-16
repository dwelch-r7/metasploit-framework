<?php
// Activation registers the same admin-only setup hooks as WordPress's plugin screen.
define('WP_ADMIN', true);
require '/opt/module-target/seed-base.php';
require_once ABSPATH . 'wp-admin/includes/file.php';
$files = json_decode(file_get_contents('/opt/module-target/files.json'), true);
foreach ($files as $fixture) {
    if (isset($fixture['create']) && !$fixture['create']) { continue; }
    $content = base64_decode($fixture['content_base64'], true);
    if ($content === false || file_put_contents($fixture['path'], $content) !== strlen($content)) {
        throw new RuntimeException('Owned Duplicator fixture creation failed');
    }
    chmod($fixture['path'], 0644);
}
$version = getenv('DUPLICATOR_RELEASE') ?: '1.3.26';
if ($version !== 'absent') {
    $releases = json_decode(file_get_contents('/opt/module-target/releases.json'), true);
    if (!isset($releases[$version]) || !hash_equals($releases[$version]['sha256'], hash_file('sha256', '/opt/module-target/plugin.zip'))) {
        throw new RuntimeException('Pinned Duplicator archive differs');
    }
    if (!WP_Filesystem()) { throw new RuntimeException('WordPress direct filesystem unavailable'); }
    $extracted = unzip_file('/opt/module-target/plugin.zip', WP_PLUGIN_DIR . '/');
    if (is_wp_error($extracted)) { throw new RuntimeException($extracted->get_error_message()); }
    $plugin = 'duplicator/duplicator.php';
    $metadata = get_plugin_data(WP_PLUGIN_DIR . '/' . $plugin, false, false);
    if ($metadata['Version'] !== $version) { throw new RuntimeException('Installed Duplicator version differs'); }
    $activated = activate_plugin($plugin);
    if (is_wp_error($activated)) { throw new RuntimeException($activated->get_error_message()); }
}
if (!wp_mkdir_p(ABSPATH . 'wp-snapshots')) { throw new RuntimeException('Local backup directory setup failed'); }
file_put_contents(ABSPATH . 'wp-snapshots/module-target-backup.txt', "Owned ordinary backup file\n");
// Exercise the fixed handler with a genuine package record, without building a
// full site backup. Only the downloadable SQL marker is a fixture; vendor
// activation, package persistence, lookup and download code remain unchanged.
if ($version === '1.3.28') {
    wp_set_current_user(get_user_by('login', 'module_admin')->ID);
    $_SERVER['SERVER_SOFTWARE'] = 'ModuleTargetNative';
    $package = new DUP_Package();
    $package->Name = 'module_target';
    $package->Hash = $package->makeHash();
    $package->NameHash = $package->Name . '_' . $package->Hash;
    $package->save('zip');
    $persisted = DUP_Package::getByID($package->ID);
    if (!$package->ID || !$persisted || $persisted->Hash !== $package->Hash) {
        throw new RuntimeException('Native Duplicator package persistence failed');
    }
    $sql = DUPLICATOR_SSDIR_PATH . '/' . $persisted->NameHash . '_database.sql';
    $bytes = "-- Owned Duplicator SQL download marker\n";
    if (file_put_contents($sql, $bytes) !== strlen($bytes)) {
        throw new RuntimeException('Owned Duplicator SQL marker creation failed');
    }
    file_put_contents('/tmp/module-target-duplicator-package.json', json_encode([
        'id' => (int) $package->ID, 'hash' => $package->Hash, 'file' => 'sql', 'path' => $sql
    ]));
}
file_put_contents('/tmp/module-target-duplicator-ready', "ready\n");
