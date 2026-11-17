<?php
define('WP_ADMIN', true);
$_SERVER['HTTP_HOST'] = 'module-target.test';
$_SERVER['REQUEST_URI'] = (getenv('LAB_PREFIX') ?: '') . '/wp-admin/plugins.php';
$_SERVER['PHP_SELF'] = '/wp-admin/plugins.php';
$_SERVER['REQUEST_METHOD'] = 'GET';
require getcwd() . '/wp-load.php';
require_once ABSPATH . 'wp-admin/includes/plugin.php';
if (!is_plugin_active('ultimate-member/ultimate-member.php')) { throw new RuntimeException('Ultimate Member activation did not persist'); }
wp_set_current_user(get_user_by('login', 'module_admin')->ID);
if (!get_option('um_core_forms') || !get_option('um_core_directories')) { throw new RuntimeException('Native activation omitted forms or directories'); }
UM()->setup()->install_default_pages();
// Configure the native directory's role selector through WordPress's post API.
// A fresh default stores an empty serialized selector; the custom-table path
// returns no members before issuing its SELECT until roles are selected.
if ((getenv('ULTIMATE_MEMBER_DIRECTORY_ROLES') ?: 'all') === 'all') {
    foreach (get_option('um_core_directories') as $directory_id) {
        update_post_meta($directory_id, '_um_roles', array_keys(wp_roles()->roles));
    }
}
$wp_rewrite->init();
update_option('rewrite_rules', $wp_rewrite->rewrite_rules());
file_put_contents(getcwd() . '/.htaccess', $wp_rewrite->mod_rewrite_rules());
