<?php
$_SERVER['HTTP_HOST'] = 'module-target.test'; $_SERVER['REQUEST_URI'] = (getenv('LAB_PREFIX') ?: '') . '/'; $_SERVER['PHP_SELF'] = '/index.php'; $_SERVER['REQUEST_METHOD'] = 'GET';
require getcwd() . '/wp-load.php'; require_once ABSPATH . 'wp-admin/includes/plugin.php';
$mode = $argv[1] ?? 'snapshot';
if ($mode === 'create-document') {
    wp_set_current_user(get_user_by('login', 'module_admin')->ID);
    $document = Depicter::documentRepository()->create('custom');
    $id = $document->getID();
    if (!$id) { throw new RuntimeException('Native document creation did not return an ID'); }
    Depicter::documentRepository()->rename($id, 'Module target native document');
    file_put_contents('/tmp/module-target-depicter-document.json', json_encode(['id' => (int)$id]));
    echo json_encode(['id' => (int)$id, 'method' => 'Depicter documentRepository create and rename']), "\n"; exit;
}
if ($mode === 'public-form-token') {
    $document = json_decode(file_get_contents('/tmp/module-target-depicter-document.json'), true);
    if (get_current_user_id() !== 0) { throw new RuntimeException('Expected genuine public form nonce context'); }
    echo json_encode(['source_id' => $document['id'], 'content_id' => '101', 'nonce' => wp_create_nonce('depicter-csrf-lead-' . $document['id']), 'user_id' => get_current_user_id()]), "\n"; exit;
}
$active = is_plugin_active('depicter/depicter.php');
$version = getenv('DEPICTER_RELEASE'); $catalog = json_decode(file_get_contents('/opt/module-target/releases.json'), true)[$version]; $hashes = [];
foreach (($active ? $catalog['installed_sha256'] : []) as $name => $expected) { $hashes[$name] = hash_file('sha256', WP_PLUGIN_DIR . '/depicter/' . $name); }
$tables = $wpdb->get_col("SHOW TABLES LIKE '" . $wpdb->esc_like($wpdb->prefix . 'depicter_') . "%'"); $schema = []; $counts = [];
foreach ($tables as $table) { $schema[$table] = $wpdb->get_results("SHOW COLUMNS FROM `$table`", ARRAY_A); $counts[$table] = (int)$wpdb->get_var("SELECT COUNT(*) FROM `$table`"); }
$leads = $active ? $wpdb->get_results('SELECT * FROM ' . $wpdb->prefix . 'depicter_leads ORDER BY id', ARRAY_A) : [];
$fields = $active ? $wpdb->get_results('SELECT * FROM ' . $wpdb->prefix . 'depicter_lead_fields ORDER BY id', ARRAY_A) : [];
echo json_encode(['core' => get_bloginfo('version'), 'php' => PHP_VERSION, 'uid' => posix_geteuid(), 'plugin_version' => $active ? get_plugin_data(WP_PLUGIN_DIR . '/depicter/depicter.php', false, false)['Version'] : null, 'prefix' => getenv('LAB_PREFIX') ?: '', 'active' => $active, 'active_plugins' => get_option('active_plugins'), 'installed_sha256' => (object)$hashes, 'archive_sha256' => hash_file('sha256', '/opt/module-target/plugin.zip'), 'group_concat_limit' => $wpdb->get_var('SELECT @@session.group_concat_max_len'), 'table_prefix' => $wpdb->prefix, 'database' => DB_NAME, 'table_counts' => (object)$counts, 'schema' => (object)$schema, 'leads' => $leads, 'lead_fields' => $fields, 'users' => $wpdb->get_results("SELECT ID,user_login,user_email,user_pass FROM {$wpdb->users} ORDER BY ID", ARRAY_A), 'db_error' => $wpdb->last_error], JSON_PRETTY_PRINT), "\n";
