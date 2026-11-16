<?php
define('WP_ADMIN', true);
$_SERVER['HTTP_HOST'] = 'module-target.test';
$_SERVER['REQUEST_URI'] = (getenv('LAB_PREFIX') ?: '') . '/wp-admin/plugins.php';
$_SERVER['PHP_SELF'] = '/wp-admin/plugins.php';
$_SERVER['REQUEST_METHOD'] = 'GET';
require getcwd() . '/wp-load.php';
wp_set_current_user(get_user_by('login', 'module_admin')->ID);
$mode = getenv('LEARNPRESS_MODE') ?: 'enabled';
$course = null;
if ($mode === 'enabled') {
    if (!post_type_exists('lp_course')) { throw new RuntimeException('Native LearnPress course type unavailable'); }
    $course = wp_insert_post([
        'post_type' => 'lp_course', 'post_status' => 'publish',
        'post_title' => 'Module target native course', 'post_name' => 'module-target-native-course',
        'post_content' => 'module-target-native-course-content', 'post_author' => get_current_user_id(),
        'comment_status' => 'closed', 'ping_status' => 'closed',
        'meta_input' => ['_lp_duration' => '2 week', '_lp_price' => '0']
    ], true);
    if (is_wp_error($course)) { throw new RuntimeException($course->get_error_message()); }
}
update_option('permalink_structure', getenv('LAB_PLAIN') === '1' ? '' : '/%postname%/');
$wp_rewrite->init();
update_option('rewrite_rules', $wp_rewrite->rewrite_rules());
file_put_contents(getcwd() . '/.htaccess', $wp_rewrite->mod_rewrite_rules());
if (getenv('LEARNPRESS_PREFIX_SCOPE') === '1') {
    if ($wpdb->prefix !== 'wp_native_') { throw new RuntimeException('Custom prefix differs'); }
    if ($wpdb->query("CREATE TABLE wp_prefix.wp_users LIKE {$wpdb->users}") === false) { throw new RuntimeException($wpdb->last_error); }
    if ($wpdb->query("INSERT INTO wp_prefix.wp_users SELECT * FROM {$wpdb->users}") !== 4) { throw new RuntimeException('Native backup row copy failed'); }
}
file_put_contents('/tmp/module-target-learnpress-ready', json_encode(['course_id' => $course]) . "\n");
