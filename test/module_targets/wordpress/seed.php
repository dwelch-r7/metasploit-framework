<?php
define('WP_INSTALLING', true);
$_SERVER['HTTP_HOST'] = 'module-target.test';
$_SERVER['REQUEST_URI'] = (getenv('LAB_PREFIX') ?: '') . '/';
require getcwd() . '/wp-load.php';
require_once ABSPATH . 'wp-admin/includes/upgrade.php';
require_once ABSPATH . 'wp-admin/includes/plugin.php';

// This owned fixture must not send installation or account mail.
add_filter('pre_wp_mail', '__return_true');
if (!is_blog_installed()) {
    $installed = wp_install('Module target WordPress', 'module_admin', 'module-admin@example.test', true, '', 'module-target-password');
    if (is_wp_error($installed)) {
        throw new RuntimeException($installed->get_error_message());
    }
    foreach (get_posts(['post_type' => 'any', 'post_status' => 'any', 'numberposts' => -1]) as $post) {
        wp_delete_post($post->ID, true);
    }
    $accounts = [
        ['module_author', 'module-target-author-password', 'author', 'Module café author'],
        ['module_subscriber', 'module-target-subscriber-password', 'subscriber', 'Module subscriber'],
        ['module_editor', 'module-target-&<café>', 'editor', 'Module editor']
    ];
    foreach ($accounts as $account) {
        $id = wp_create_user($account[0], $account[1], str_replace('_', '-', $account[0]) . '@example.test');
        if (is_wp_error($id)) {
            throw new RuntimeException($id->get_error_message());
        }
        $changed = wp_update_user(['ID' => $id, 'role' => $account[2], 'display_name' => $account[3]]);
        if (is_wp_error($changed)) {
            throw new RuntimeException($changed->get_error_message());
        }
    }
    $author = get_user_by('login', 'module_author');
    $post_id = wp_insert_post([
        'post_title' => 'Module target native post', 'post_name' => 'module-target-post',
        'post_content' => 'module-target-native-post-content', 'post_author' => $author->ID,
        'post_status' => 'publish', 'comment_status' => 'closed', 'ping_status' => 'closed'
    ], true);
    if (is_wp_error($post_id)) {
        throw new RuntimeException($post_id->get_error_message());
    }
    update_option('permalink_structure', getenv('LAB_PLAIN') === '1' ? '' : '/%postname%/');
}
// Installation runs without an HTTP request. Store the real subdirectory so
// WordPress itself generates the corresponding Apache rewrite base.
$installed_url = 'http://module-target.test' . (getenv('LAB_PREFIX') ?: '');
update_option('home', $installed_url);
update_option('siteurl', $installed_url);
$wp_rewrite->init();
update_option('rewrite_rules', $wp_rewrite->rewrite_rules());
// CLI has no Apache request for save_mod_rewrite_rules() to inspect. Render
// WordPress's own rules at the actual installation root instead.
file_put_contents(getcwd() . '/.htaccess', $wp_rewrite->mod_rewrite_rules());
file_put_contents('/tmp/module-target-ready', "ready\n");
