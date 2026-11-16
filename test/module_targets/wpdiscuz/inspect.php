<?php
$_SERVER['HTTP_HOST'] = 'module-target.test';
$_SERVER['REQUEST_URI'] = (getenv('LAB_PREFIX') ?: '') . '/';
$_SERVER['PHP_SELF'] = (getenv('LAB_PREFIX') ?: '') . '/index.php';
$_SERVER['REQUEST_METHOD'] = 'GET';
require getcwd() . '/wp-load.php';
require_once ABSPATH . 'wp-admin/includes/plugin.php';
$mode = $argv[1] ?? 'snapshot';
if ($mode === 'cleanup') {
    $ids = ($argv[2] ?? '') === '' ? [] : explode(',', $argv[2]);
    $removed = [];
    foreach ($ids as $id) {
        if (!ctype_digit($id) || get_post_type((int) $id) !== 'attachment') { throw new RuntimeException('Invalid owned attachment cleanup ID'); }
        $file = get_attached_file((int) $id);
        $result = wp_delete_attachment((int) $id, true);
        if (!$result || file_exists($file)) { throw new RuntimeException('Owned attachment cleanup failed'); }
        $removed[] = (int) $id;
    }
    if (file_exists('/tmp/module-target-wpdiscuz-native-proof')) { unlink('/tmp/module-target-wpdiscuz-native-proof'); }
    if (file_exists('/tmp/module-target-wpdiscuz-owner-proof')) { unlink('/tmp/module-target-wpdiscuz-owner-proof'); }
    echo json_encode(['removed' => $removed]), "\n";
    exit;
}
$meta = json_decode(file_get_contents('/tmp/module-target-wpdiscuz-post.json'), true);
$post = get_post($meta['id']);
$plugin = 'wpdiscuz/class.WpdiscuzCore.php';
$active = is_plugin_active($plugin);
$core = $active ? wpDiscuz() : null;
$uploads = wp_upload_dir();
$installed = [];
foreach (['readme.txt', 'class.WpdiscuzCore.php', 'utils/class.WpdiscuzHelperUpload.php'] as $name) { $installed[$name] = $active ? hash_file('sha256', WP_PLUGIN_DIR . '/wpdiscuz/' . $name) : null; }
$attachments = [];
foreach (get_posts(['post_type' => 'attachment', 'post_status' => 'any', 'posts_per_page' => -1, 'orderby' => 'ID', 'order' => 'ASC']) as $attachment) {
    $file = get_attached_file($attachment->ID);
    $attachments[] = ['id' => $attachment->ID, 'title' => $attachment->post_title, 'excerpt' => $attachment->post_excerpt, 'mime' => $attachment->post_mime_type, 'path' => $file, 'exists' => file_exists($file), 'size' => file_exists($file) ? filesize($file) : null, 'sha256' => file_exists($file) ? hash_file('sha256', $file) : null];
}
$user = get_user_by('login', 'module_admin');
echo json_encode([
    'core' => get_bloginfo('version'), 'php' => PHP_VERSION, 'uid' => posix_geteuid(), 'prefix' => getenv('LAB_PREFIX') ?: '',
    'version' => $active ? get_plugin_data(WP_PLUGIN_DIR . '/' . $plugin, false, false)['Version'] : null, 'active' => is_plugin_active($plugin),
    'active_plugins' => get_option('active_plugins'), 'archive_sha256' => $active ? hash_file('sha256', '/opt/module-target/plugin.zip') : null, 'installed_sha256' => $installed,
    'post' => ['id' => $post->ID, 'slug' => $post->post_name, 'type' => $post->post_type, 'status' => $post->post_status, 'comments' => $post->comment_status, 'path' => parse_url(get_permalink($post), PHP_URL_PATH)],
    'uploads' => ['path' => $uploads['path'], 'base' => $uploads['basedir'], 'writable' => is_writable($uploads['path']), 'yearmonth' => get_option('uploads_use_yearmonth_folders'), 'option_path' => get_option('upload_path')],
    'upload_enabled' => $core ? $core->options->content['wmuIsEnabled'] : null, 'guest_upload_enabled' => $core ? $core->options->content['wmuIsGuestAllowed'] : null,
    'user_hash' => hash('sha256', $user->user_pass), 'attachments' => $attachments,
    'owner_proof' => file_exists('/tmp/module-target-wpdiscuz-owner-proof') ? file_get_contents('/tmp/module-target-wpdiscuz-owner-proof') : null, 'native_proof' => file_exists('/tmp/module-target-wpdiscuz-native-proof') ? file_get_contents('/tmp/module-target-wpdiscuz-native-proof') : null
], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES), "\n";
