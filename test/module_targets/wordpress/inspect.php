<?php
$_SERVER['HTTP_HOST'] = 'module-target.test';
$_SERVER['REQUEST_URI'] = (getenv('LAB_PREFIX') ?: '') . '/';
require getcwd() . '/wp-load.php';
require_once ABSPATH . 'wp-admin/includes/plugin.php';
global $wp_version;
$plugins = [];
foreach (get_plugins() as $path => $data) {
    $plugins[$path] = ['version' => $data['Version'], 'active' => is_plugin_active($path)];
}
$themes = [];
foreach (wp_get_themes() as $slug => $theme) {
    $themes[$slug] = ['version' => $theme->get('Version'), 'name' => $theme->get('Name')];
}
$users = [];
foreach (get_users(['orderby' => 'ID']) as $user) {
    $users[] = ['id' => $user->ID, 'login' => $user->user_login, 'slug' => $user->user_nicename, 'name' => $user->display_name, 'roles' => $user->roles];
}
$passwords = [
    'module_admin' => 'module-target-password',
    'module_author' => 'module-target-author-password',
    'module_subscriber' => 'module-target-subscriber-password',
    'module_editor' => 'module-target-&<café>'
];
$authentication = [];
foreach ($passwords as $login => $password) {
    $valid = wp_authenticate($login, $password);
    $wrong = wp_authenticate($login, 'module-target-wrong-password');
    if (is_wp_error($valid) || !is_wp_error($wrong)) {
        throw new RuntimeException('Native authentication policy differs: ' . $login);
    }
    $authentication[$login] = ['id' => $valid->ID, 'wrong_error' => $wrong->get_error_code()];
}
$missing = wp_authenticate('module_target_missing', 'module-target-password');
if (!is_wp_error($missing)) {
    throw new RuntimeException('Native absent account authenticated');
}
echo json_encode([
    'version' => $wp_version, 'php' => PHP_VERSION, 'plugins' => $plugins, 'themes' => $themes,
    'users' => $users, 'authentication' => $authentication,
    'permalink_structure' => get_option('permalink_structure'), 'rest_url' => rest_url('wp/v2/users'),
    'posts' => array_map(function ($post) { return ['id' => $post->ID, 'author' => $post->post_author, 'title' => $post->post_title, 'content' => $post->post_content, 'link' => get_permalink($post)]; }, get_posts(['post_status' => 'publish']))
], JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR) . "\n";
