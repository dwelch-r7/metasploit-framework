<?php
require '/opt/module-target/seed-base.php';
require_once ABSPATH . 'wp-admin/includes/user.php';
if (getenv('WP2SHELL_SINGLE_USER') === '1') {
    $administrator = get_user_by('login', 'module_admin');
    foreach (get_users() as $user) {
        if ($user->ID !== $administrator->ID && !wp_delete_user($user->ID, $administrator->ID)) { throw new RuntimeException('Native user removal failed'); }
    }
}
if (getenv('WP2SHELL_NO_POSTS') === '1') {
    foreach (get_posts(['post_type' => 'any', 'post_status' => 'any', 'numberposts' => -1]) as $post) {
        if (!wp_delete_post($post->ID, true)) { throw new RuntimeException('Native post removal failed'); }
    }
}
