<?php
// Use the same activation context as WordPress's administrator plugin screen.
define('WP_ADMIN', true);
$_SERVER['REQUEST_METHOD'] = 'GET';
$_SERVER['PHP_SELF'] = (getenv('LAB_PREFIX') ?: '') . '/wp-admin/plugins.php';
require '/opt/module-target/seed-base.php';
require_once ABSPATH . 'wp-admin/includes/file.php';
wp_set_current_user(get_user_by('login', 'module_admin')->ID);
$style = getenv('LAB_UPLOAD_STYLE') ?: 'dated';
if ($style === 'flat') {
    update_option('uploads_use_yearmonth_folders', 0);
} elseif ($style === 'custom') {
    update_option('uploads_use_yearmonth_folders', 0);
    update_option('upload_path', 'wp-content/module-target-media');
}
$version = getenv('WPDISCUZ_RELEASE') ?: '7.0.4';
if ($version !== 'absent') {
$catalog = json_decode(file_get_contents('/opt/module-target/releases.json'), true);
if (!isset($catalog[$version]) || !hash_equals($catalog[$version]['sha256'], hash_file('sha256', '/opt/module-target/plugin.zip'))) {
    throw new RuntimeException('Pinned wpDiscuz archive differs');
}
if (!WP_Filesystem()) { throw new RuntimeException('WordPress direct filesystem unavailable'); }
$result = unzip_file('/opt/module-target/plugin.zip', WP_PLUGIN_DIR . '/');
if (is_wp_error($result)) { throw new RuntimeException($result->get_error_message()); }
$plugin = 'wpdiscuz/class.WpdiscuzCore.php';
if (get_plugin_data(WP_PLUGIN_DIR . '/' . $plugin, false, false)['Version'] !== $version) {
    throw new RuntimeException('Installed wpDiscuz version differs');
}
$result = activate_plugin($plugin);
if (is_wp_error($result)) { throw new RuntimeException($result->get_error_message()); }
    if (getenv('LAB_GUEST_DISABLED') === '1') {
        wpDiscuz()->options->content['wmuIsGuestAllowed'] = 0;
        wpDiscuz()->options->updateOptions();
    }
}
$post = get_page_by_path('module-target-post', OBJECT, 'post');
if (getenv('LAB_POST_ONE') === '1') {
    $id = wp_insert_post([
        'import_id' => 1, 'post_title' => 'Module target wpDiscuz post one',
        'post_name' => 'module-target-post-one', 'post_content' => 'module-target-wpdiscuz-content',
        'post_status' => 'publish', 'comment_status' => 'open'
    ], true);
    if (is_wp_error($id) || $id !== 1) { throw new RuntimeException('Native imported post one setup failed'); }
    $post = get_post($id);
} else {
    $result = wp_update_post(['ID' => $post->ID, 'comment_status' => 'open'], true);
    if (is_wp_error($result)) { throw new RuntimeException($result->get_error_message()); }
    $post = get_post($post->ID);
}
file_put_contents('/tmp/module-target-wpdiscuz-post.json', json_encode(['id' => $post->ID, 'slug' => $post->post_name]));
// CLI setup runs as root; give the web worker the normal ownership required
// for genuine uploads and the plugin's generated assets. Vendor bytes stay intact.
$uploads = wp_upload_dir();
foreach ([WP_PLUGIN_DIR . '/wpdiscuz', $uploads['basedir']] as $directory) {
    if (!is_dir($directory)) { continue; }
    chown($directory, 'www-data');
    chgrp($directory, 'www-data');
    foreach (new RecursiveIteratorIterator(new RecursiveDirectoryIterator($directory, FilesystemIterator::SKIP_DOTS), RecursiveIteratorIterator::SELF_FIRST) as $file) {
        chown($file->getPathname(), 'www-data');
        chgrp($file->getPathname(), 'www-data');
    }
}
if (!wp_mkdir_p('/tmp/module-target-wpdiscuz-proofs')) { throw new RuntimeException('Owned proof directory creation failed'); }
chown('/tmp/module-target-wpdiscuz-proofs', 'www-data');
chgrp('/tmp/module-target-wpdiscuz-proofs', 'www-data');
file_put_contents('/tmp/module-target-wpdiscuz-ready', "ready\n");
