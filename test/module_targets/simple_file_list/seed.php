<?php
define('WP_ADMIN', true);
$_SERVER['REQUEST_METHOD'] = 'GET';
$_SERVER['PHP_SELF'] = '/wp-admin/plugins.php';
require '/opt/module-target/seed-base.php';
require_once ABSPATH.'wp-admin/includes/file.php';
wp_set_current_user(get_user_by('login','module_admin')->ID);
if (!WP_Filesystem() || posix_geteuid() !== 33) { throw new RuntimeException('Native filesystem identity differs'); }
$release = json_decode(file_get_contents('/opt/module-target/releases.json'),true,512,JSON_THROW_ON_ERROR)[getenv('SFL_RELEASE')];
if (!hash_equals($release['sha256'],hash_file('sha256','/opt/module-target/plugin.zip'))) { throw new RuntimeException('Native archive differs'); }
$result = unzip_file('/opt/module-target/plugin.zip',WP_PLUGIN_DIR.'/');
if (is_wp_error($result)) { throw new RuntimeException($result->get_error_message()); }
foreach ($release['installed_sha256'] as $path=>$digest) {
    if (!is_file(WP_PLUGIN_DIR.'/simple-file-list/'.$path) || !hash_equals($digest,hash_file('sha256',WP_PLUGIN_DIR.'/simple-file-list/'.$path))) { throw new RuntimeException('Installed source differs: '.$path); }
}
echo "Native archive extracted and verified\n";
