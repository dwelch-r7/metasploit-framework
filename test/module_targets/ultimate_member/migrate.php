<?php
define('WP_ADMIN', true);
define('DOING_AJAX', true);
$_SERVER['HTTP_HOST'] = 'module-target.test';
$_SERVER['REQUEST_URI'] = (getenv('LAB_PREFIX') ?: '') . '/wp-admin/admin-ajax.php';
$_SERVER['PHP_SELF'] = '/wp-admin/admin-ajax.php';
$_SERVER['REQUEST_METHOD'] = 'POST';
require getcwd() . '/wp-load.php';
wp_set_current_user(get_user_by('login', 'module_admin')->ID);
if (!current_user_can('manage_options')) { throw new RuntimeException('Native migration requires the owned administrator'); }
$callback = $argv[1] ?? '';
if (!in_array($callback, ['um_usermeta_fields', 'um_update_metadata_per_page'], true)) { throw new RuntimeException('Unknown native migration stage'); }
$_POST = ['cb_func' => $callback, 'page' => 1];
$_REQUEST = $_POST + ['nonce' => wp_create_nonce('um-admin-nonce')];
// Execute the vendor's real nonce-checked configuration/migration operation.
// Separate processes let the native member-directory class follow the setting.
UM()->admin_settings()->same_page_update_ajax();
throw new RuntimeException('Native migration did not return its JSON result');
