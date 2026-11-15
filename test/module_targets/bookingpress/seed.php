<?php
require '/opt/module-target/seed-base.php';
require_once ABSPATH . 'wp-admin/includes/file.php';
if (getenv('BOOKINGPRESS_MODE') !== 'absent') {
$version = getenv('BOOKINGPRESS_RELEASE') ?: '1.0.10';
$releases = json_decode(file_get_contents('/opt/module-target/releases.json'), true);
if (!isset($releases[$version]) || !hash_equals($releases[$version]['sha256'], hash_file('sha256', '/opt/module-target/plugin.zip'))) {
    throw new RuntimeException('Pinned BookingPress archive differs');
}
if (!WP_Filesystem()) { throw new RuntimeException('WordPress direct filesystem unavailable'); }
$extracted = unzip_file('/opt/module-target/plugin.zip', WP_PLUGIN_DIR . '/');
if (is_wp_error($extracted)) { throw new RuntimeException($extracted->get_error_message()); }
$plugin = 'bookingpress-appointment-booking/bookingpress-appointment-booking.php';
$metadata = get_plugin_data(WP_PLUGIN_DIR . '/' . $plugin, false, false);
if ($metadata['Version'] !== $version) { throw new RuntimeException('Installed BookingPress version differs'); }
$activated = activate_plugin($plugin);
if (is_wp_error($activated)) { throw new RuntimeException($activated->get_error_message()); }
// Populate ordinary records after the vendor activation creates its schema.
// Use category 7 so native proof does not depend on the module's fixed ID 1.
$category = [
    'bookingpress_category_id' => 7, 'bookingpress_category_name' => 'Owned appointment category',
    'bookingpress_category_position' => 0, 'bookingpress_categorydate_created' => '2022-03-01 00:00:00'
];
if ($wpdb->insert($wpdb->prefix . 'bookingpress_categories', $category) !== 1) {
    throw new RuntimeException('BookingPress category setup failed: ' . $wpdb->last_error);
}
$service = [
    'bookingpress_service_id' => 11, 'bookingpress_category_id' => 7,
    'bookingpress_service_name' => 'Owned appointment service', 'bookingpress_service_price' => 25,
    'bookingpress_service_duration_val' => 30, 'bookingpress_service_duration_unit' => 'm',
    'bookingpress_service_description' => 'Ordinary native appointment', 'bookingpress_service_position' => 0,
    'bookingpress_servicedate_created' => '2022-03-01 00:00:00'
];
if ($wpdb->insert($wpdb->prefix . 'bookingpress_services', $service) !== 1) {
    throw new RuntimeException('BookingPress service setup failed: ' . $wpdb->last_error);
}
}
$page = wp_insert_post([
    'post_type' => 'page', 'post_title' => 'Owned BookingPress page', 'post_name' => 'bookingpress',
    'post_content' => '[bookingpress_form]', 'post_status' => 'publish', 'comment_status' => 'closed'
], true);
if (is_wp_error($page)) { throw new RuntimeException($page->get_error_message()); }
$wp_rewrite->init();
update_option('rewrite_rules', $wp_rewrite->rewrite_rules());
file_put_contents(getcwd() . '/.htaccess', $wp_rewrite->mod_rewrite_rules());
file_put_contents('/tmp/module-target-bookingpress-ready', "ready\n");
