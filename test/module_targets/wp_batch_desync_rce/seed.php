<?php
require '/opt/module-target/seed-core.php';
if (getenv('LAB_PAGE_ONLY') === '1') {
    foreach (get_posts(['post_type' => 'post', 'post_status' => 'any', 'numberposts' => -1]) as $post) {
        if (!wp_delete_post($post->ID, true)) { throw new RuntimeException('Native published-post removal failed'); }
    }
    $administrator = get_user_by('login', 'module_admin');
    $page = wp_insert_post([
        'post_title' => 'Module target native page',
        'post_name' => 'module-target-page',
        'post_status' => 'publish',
        'post_type' => 'page',
        'post_author' => $administrator->ID,
        'post_content' => 'Native page for the oEmbed fallback path.'
    ], true);
    if (is_wp_error($page) || !$page) { throw new RuntimeException('Native published-page creation failed'); }
}
