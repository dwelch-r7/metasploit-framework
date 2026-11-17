<?php
define('WP_ADMIN', true);
$_SERVER['HTTP_HOST'] = 'module-target.test';
$_SERVER['REQUEST_URI'] = (getenv('LAB_PREFIX') ?: '') . '/wp-admin/plugins.php';
$_SERVER['PHP_SELF'] = '/wp-admin/plugins.php';
$_SERVER['REQUEST_METHOD'] = 'GET';
require getcwd() . '/wp-load.php';
if ((getenv('ULTIMATE_MEMBER_MODE') ?: 'enabled') !== 'enabled') {
    file_put_contents('/tmp/module-target-ultimate-member-ready', "ready\n");
    return;
}
if (getenv('ULTIMATE_MEMBER_CUSTOM_META') === '0') {
    if (UM()->options()->get('member_directory_own_table')) { throw new RuntimeException('Custom metadata unexpectedly enabled'); }
    file_put_contents('/tmp/module-target-ultimate-member-ready', "ready\n");
    return;
}
if (!UM()->options()->get('member_directory_own_table')) { throw new RuntimeException('Native custom metadata option is disabled'); }
if (get_class(UM()->member_directory()) !== 'um\\core\\Member_Directory_Meta') { throw new RuntimeException('Native metadata implementation is not selected'); }
$keys = get_option('um_usermeta_fields', []);
if (!$keys || !in_array('um_member_directory_data', $keys, true)) { throw new RuntimeException('Native metadata key list is incomplete'); }
$core = $wpdb->get_results('SELECT user_id,meta_key,meta_value FROM ' . $wpdb->usermeta . ' WHERE meta_key IN (\'' . implode("','", array_map('esc_sql', $keys)) . '\') ORDER BY user_id,meta_key,meta_value', ARRAY_A);
$custom = $wpdb->get_results('SELECT user_id,um_key AS meta_key,um_value AS meta_value FROM ' . $wpdb->prefix . 'um_metadata ORDER BY user_id,um_key,um_value', ARRAY_A);
if (!$core || $core !== $custom) { throw new RuntimeException('Vendor migration does not match native core metadata'); }
file_put_contents('/tmp/module-target-ultimate-member-ready', "ready\n");
